package beater

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"strings"
	"time"
	"net/http"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/sqs"

	"github.com/elastic/beats/libbeat/beat"
	"github.com/elastic/beats/libbeat/cfgfile"
	"github.com/elastic/beats/libbeat/common"
	"github.com/elastic/beats/libbeat/logp"
	"github.com/elastic/beats/libbeat/publisher"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const logTimeFormat = "2006-01-02T15:04:05Z"

// S3AwsLogBeat contains configuration options specific to the current
//  running instance as defined in cmd line arguments and the configuration
//  file.
type S3AwsLogBeat struct {
	version			string
	sqsURL			string
	awsConfig		*aws.Config
	numQueueFetch	int
	sleepTime		time.Duration
	noPurge			bool
	logMode			string

	backfillBucket	string
	backfillPrefix	string

	S3AwsLogBeatConfig	ConfigSettings
	CmdLineArgs			CmdLineArgs
	events				publisher.Client
	done				chan struct{}

	filesProcessed			prometheus.Counter
	filesProcessedErrors	prometheus.Counter
	eventsProcessed			prometheus.Counter
	eventsProcessedErrors	prometheus.Counter
	info					prometheus.Gauge
}

// CmdLineArgs is used by the flag package to parse custom flags specific
//  to S3AwsLogBeat
type CmdLineArgs struct {
	backfillBucket		*string
	backfillPrefix		*string
}

var cmdLineArgs CmdLineArgs

// SQS message extracted from raw sqs event Body
type sqsMessage struct {
	Type				string
	MessageID			string
	TopicArn			string
	Message				string
	Timestamp			string
	SignatureVersion	string
	Signature			string
	SigningCertURL		string
	UnsubscribeURL		string
}

// S3 Logfile specific information extracted from sqsMessage and sqsMessage.Message
type s3awslogMessage struct {
	S3Bucket		string		`json:"s3Bucket"`
	S3ObjectKey		[]string	`json:"s3ObjectKey"`
	MessageID		string		`json:",omitempty"`
	ReceiptHandle	string		`json:",omitempty"`
}

// data struct matching the defined fields of a CloudTrail Record as
//  described in:
//  http://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-record-contents.html
type cloudtrailLog struct {
	Records []cloudtrailEvent
}
type cloudtrailEvent struct {
	EventTime			string					`json:"eventTime"`
	EventVersion		string					`json:"eventVersion"`
	EventSource			string					`json:"eventSource"`
	UserIdentity		map[string]interface{}	`json:"userIdentity"`
	EventName			string					`json:"eventName"`
	AwsRegion			string					`json:"awsRegion"`
	SourceIPAddress		string					`json:"sourceIPAddress"`
	UserAgent			string					`json:"userAgent"`
	ErrorCode			string					`json:"errorCode"`
	ErrorMessage		string					`json:"errorMessage,omitempty"`
	RequestParameters	map[string]interface{}	`json:"requestParameters"`
	RequestID			string					`json:"requestID"`
	EventID				string					`json:"eventID"`
	EventType			string					`json:"eventType"`
	APIVersion			string					`json:"apiVersion"`
	RecipientAccountID	string					`json:"recipientAccountID"`
}

func init() {
	cmdLineArgs = CmdLineArgs{
		backfillBucket: flag.String("b", "", "Name of S3 bucket used for backfilling"),
		backfillPrefix: flag.String("p", "", "Prefix to be used when listing objects from S3 bucket"),
	}
}

func New() *S3AwsLogBeat {
	logbeat := &S3AwsLogBeat{}
	logbeat.CmdLineArgs = cmdLineArgs

	logbeat.filesProcessed = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "s3_awslogs_beat_files",
			Help: "The total number of S3 files with events processed",
		})
	logbeat.filesProcessedErrors = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "s3_awslogs_beat_file_errors",
			Help: "The total number of errors ingesting S3 files with events",
		})

	logbeat.eventsProcessed = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "s3_awslogs_beat_events",
			Help: "The total number of published events",
		})
	logbeat.eventsProcessedErrors = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "s3_awslogs_beat_events_errors",
			Help: "The total number of errors with publishing events",
		})

	return logbeat
}

func (logbeat *S3AwsLogBeat) Config(b *beat.Beat) error {
	if err := cfgfile.Read(&logbeat.S3AwsLogBeatConfig, ""); err != nil {
		logp.Err("Error reading configuration file: %v", err)
		return err
	}

	//Validate and instantiate configuration file variables
	if logbeat.S3AwsLogBeatConfig.Input.SQSUrl != nil {
		logbeat.sqsURL = *logbeat.S3AwsLogBeatConfig.Input.SQSUrl
	} else {
		return errors.New("Invalid SQS URL in configuration file")
	}

	if logbeat.S3AwsLogBeatConfig.Input.NumQueueFetch != nil {
		logbeat.numQueueFetch = *logbeat.S3AwsLogBeatConfig.Input.NumQueueFetch
	} else {
		logbeat.numQueueFetch = 1
	}

	if logbeat.S3AwsLogBeatConfig.Input.SleepTime != nil {
		logbeat.sleepTime = time.Duration(*logbeat.S3AwsLogBeatConfig.Input.SleepTime) * time.Second
	} else {
		logbeat.sleepTime = time.Minute * 5
	}

	if logbeat.S3AwsLogBeatConfig.Input.NoPurge != nil {
		logbeat.noPurge = *logbeat.S3AwsLogBeatConfig.Input.NoPurge
	} else {
		logbeat.noPurge = false
	}

	if logbeat.S3AwsLogBeatConfig.Input.LogMode != nil {
		logbeat.logMode = *logbeat.S3AwsLogBeatConfig.Input.LogMode
	} else {
		logbeat.logMode = "cloudtrail"
	}

	// use AWS credentials from configuration file if provided, fall back to ENV and ~/.aws/credentials
	if logbeat.S3AwsLogBeatConfig.Input.AWSCredentialProvider != nil {
		logbeat.awsConfig = &aws.Config{
			Credentials: credentials.NewSharedCredentials("", "logbeat.S3AwsLogBeatConfig.Input.AWSCredentialProvider"),
		}
	} else {
		logbeat.awsConfig = aws.NewConfig()
	}

	if logbeat.S3AwsLogBeatConfig.Input.AWSRegion != nil {
		logbeat.awsConfig = logbeat.awsConfig.WithRegion(*logbeat.S3AwsLogBeatConfig.Input.AWSRegion)
	}

	// parse cmd line flags to determine if backfill or queue mode is being used
	if logbeat.CmdLineArgs.backfillBucket != nil {
		logbeat.backfillBucket = *logbeat.CmdLineArgs.backfillBucket

		if logbeat.CmdLineArgs.backfillPrefix != nil {
			logbeat.backfillPrefix = *logbeat.CmdLineArgs.backfillPrefix
		}
	}

	logbeat.version = b.Version
	logbeat.info = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "s3_awslogs_info",
			Help: "Information about the running S3 AWS Logs Beat configuration",
			ConstLabels: prometheus.Labels{"log_mode": logbeat.logMode, "version": logbeat.version},
		})
	logbeat.info.Set(1)

	logp.Debug("s3awslogbeat", "Init s3awslogbeat")
	logp.Debug("s3awslogbeat", "SQS Url: %s", logbeat.sqsURL)
	logp.Debug("s3awslogbeat", "Log Mode: %s", logbeat.logMode)
	logp.Debug("s3awslogbeat", "Number of items to fetch from queue: %d", logbeat.numQueueFetch)
	logp.Debug("s3awslogbeat", "Time to sleep when queue is empty: %.0f", logbeat.sleepTime.Seconds())
	logp.Debug("s3awslogbeat", "Events will be deleted from SQS when processed: %t", logbeat.noPurge)
	logp.Debug("s3awslogbeat", "Backfill bucket: %s", logbeat.backfillBucket)
	logp.Debug("s3awslogbeat", "Backfill prefix: %s", logbeat.backfillPrefix)

	return nil
}

func (logbeat *S3AwsLogBeat) Setup(b *beat.Beat) error {
	logbeat.events = b.Events
	logbeat.done = make(chan struct{})
	return nil
}

func (logbeat *S3AwsLogBeat) Run(b *beat.Beat) error {
	http.Handle("/metrics", promhttp.Handler())
	go http.ListenAndServe(":9400", nil)

	if logbeat.backfillBucket != "" {
		logp.Info("Running in backfill mode")
		if err := logbeat.runBackfill(); err != nil {
			return fmt.Errorf("Error backfilling logs: %s", err)
		}
	} else {
		logp.Info("Running in queue mode")
		if err := logbeat.runQueue(); err != nil {
			return fmt.Errorf("Error processing queue: %s", err)
		}
	}
	return nil
}

func (logbeat *S3AwsLogBeat) runQueue() error {
	for {
		select {
		case <-logbeat.done:
			return nil
		default:
		}

		messages, err := logbeat.fetchMessages()
		if err != nil {
			logp.Err("Error fetching messages from SQS: %v", err)
			break
		}

		if len(messages) == 0 {
			logp.Info("No new events to process, sleeping for %.0f seconds", logbeat.sleepTime.Seconds())
			time.Sleep(logbeat.sleepTime)
			continue
		}

		logp.Info("Fetched %d new events from SQS.", len(messages))
		// fetch and process each log file
		for _, m := range messages {
			logp.Info("Downloading and processing log file: s3://%s/%s", m.S3Bucket, m.S3ObjectKey)
			lf, err := logbeat.readCloudTrailLogfile(m)
			if err != nil {
				logbeat.filesProcessedErrors.Inc()
				logp.Err("Error reading log file [id: %s]: %s", m.MessageID, err)
				continue
			}
			logbeat.filesProcessed.Inc()

			if err := logbeat.publishCloudTrailEvents(lf); err != nil {
				logp.Err("Error publishing events [id: %s]: %s", m.MessageID, err)
				continue
			}
			if !logbeat.noPurge {
				if err := logbeat.deleteMessage(m); err != nil {
					logp.Err("Error deleting proccessed SQS event [id: %s]: %s", m.MessageID, err)
				}
			}
		}
	}

	return nil
}

func (logbeat *S3AwsLogBeat) runBackfill() error {
	logp.Info("Backfilling using S3 bucket: s3://%s/%s", logbeat.backfillBucket, logbeat.backfillPrefix)

	s := s3.New(session.New(logbeat.awsConfig))
	q := s3.ListObjectsInput{
		Bucket: aws.String(logbeat.backfillBucket),
		Prefix: aws.String(logbeat.backfillPrefix),
	}

	if list, err := s.ListObjects(&q); err == nil {
		for _, e := range list.Contents {
			if strings.HasSuffix(*e.Key, ".json.gz") {
				logp.Info("Found log file to add to queue: %s", *e.Key)
				if err := logbeat.pushQueue(logbeat.backfillBucket, *e.Key); err != nil {
					logp.Err("Failed to push log file onto queue: %s", err)
					return fmt.Errorf("Queue push failed: %s", err)
				}
			}
		}
	} else {
		logp.Err("Unable to list objects in bucket: %s", err)
		return fmt.Errorf("Failed to list bucket objects: %s", err)
	}
	return nil
}

func (logbeat *S3AwsLogBeat) pushQueue(bucket, key string) error {
	body := s3awslogMessage{
		S3Bucket:	bucket,
		S3ObjectKey: []string{key},
	}
	b, err := json.Marshal(body)
	if err != nil {
		return err
	}

	msg := sqsMessage{Message: string(b)}
	m, err := json.Marshal(msg)
	if err != nil {
		return err
	}

	q := sqs.New(session.New(logbeat.awsConfig))
	_, err = q.SendMessage(&sqs.SendMessageInput{
		QueueUrl:	aws.String(logbeat.sqsURL),
		MessageBody: aws.String(string(m)),
	})
	if err != nil {
		return err
	}

	return nil
}

func (logbeat *S3AwsLogBeat) Stop() {
	close(logbeat.done)
}

func (logbeat *S3AwsLogBeat) Cleanup(b *beat.Beat) error {
	return nil
}

func (logbeat *S3AwsLogBeat) publishCloudTrailEvents(logs cloudtrailLog) error {
	if len(logs.Records) < 1 {
		return nil
	}

	events := make([]common.MapStr, 0, len(logs.Records))

	for _, logEvent := range logs.Records {
		timestamp, err := time.Parse(logTimeFormat, logEvent.EventTime)

		if err != nil {
			logp.Err("Unable to parse EventTime : %s", logEvent.EventTime)
		}

		logp.Info("Event Type: %v", logEvent['UserIdentity']['Type'])

		le := common.MapStr{
			"@timestamp": common.Time(timestamp),
			"type":	   "CloudTrail",
			"cloudtrail": logEvent,
		}

		events = append(events, le)
	}
	if !logbeat.events.PublishEvents(events, publisher.Sync, publisher.Guaranteed) {
		logbeat.eventsProcessedErrors.Add(float64(len(events)))
		return fmt.Errorf("Error publishing events")
	}
	logbeat.eventsProcessed.Add(float64(len(events)))

	return nil
}

func (logbeat *S3AwsLogBeat) readCloudTrailLogfile(m s3awslogMessage) (cloudtrailLog, error) {
	events := cloudtrailLog{}

	s := s3.New(session.New(logbeat.awsConfig))
	q := s3.GetObjectInput{
		Bucket: aws.String(m.S3Bucket),
		Key:	aws.String(m.S3ObjectKey[0]),
	}
	o, err := s.GetObject(&q)
	if err != nil {
		return events, err
	}
	b, err := ioutil.ReadAll(o.Body)
	if err != nil {
		return events, err
	}

	if err := json.Unmarshal(b, &events); err != nil {
		return events, fmt.Errorf("Error unmarshaling cloutrail JSON: %s", err.Error())
	}

	return events, nil
}

func (logbeat *S3AwsLogBeat) fetchMessages() ([]s3awslogMessage, error) {
	var m []s3awslogMessage

	q := sqs.New(session.New(logbeat.awsConfig))
	params := &sqs.ReceiveMessageInput{
		QueueUrl:			aws.String(logbeat.sqsURL),
		MaxNumberOfMessages: aws.Int64(int64(logbeat.numQueueFetch)),
	}

	resp, err := q.ReceiveMessage(params)
	if err != nil {
		return m, fmt.Errorf("SQS ReceiveMessage error: %s", err.Error())
	}

	//no new messages in queue
	if len(resp.Messages) == 0 {
		return nil, nil
	}

	for _, e := range resp.Messages {
		tmsg := sqsMessage{}
		if err := json.Unmarshal([]byte(*e.Body), &tmsg); err != nil {
			return nil, fmt.Errorf("SQS message JSON parse error [id: %s]: %s", *e.MessageId, err.Error())
		}

		event := s3awslogMessage{}
		if err := json.Unmarshal([]byte(tmsg.Message), &event); err != nil {
			return nil, fmt.Errorf("SQS body JSON parse error [id: %s]: %s", *e.MessageId, err.Error())
		}

		if tmsg.Message == "CloudTrail validation message." {
			if !logbeat.noPurge {
				if err := logbeat.deleteMessage(event); err != nil {
					return nil, fmt.Errorf("Error deleting 'validation message' [id: %s]: %s", tmsg.MessageID, err)
				}
			}
			continue
		}

		event.MessageID = tmsg.MessageID
		event.ReceiptHandle = *e.ReceiptHandle

		m = append(m, event)
	}

	return m, nil
}

func (logbeat *S3AwsLogBeat) deleteMessage(m s3awslogMessage) error {
	q := sqs.New(session.New(logbeat.awsConfig))
	params := &sqs.DeleteMessageInput{
		QueueUrl:	  aws.String(logbeat.sqsURL),
		ReceiptHandle: aws.String(m.ReceiptHandle),
	}

	_, err := q.DeleteMessage(params)
	if err != nil {
		return err
	}

	return nil
}
