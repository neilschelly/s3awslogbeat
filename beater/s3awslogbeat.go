package beater

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
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
	awsSQSConfig	*aws.Config
	awsS3Config		*aws.Config
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
	csvFields			map[string]int // used for mapping fields in vpcflowlog

	notificationsProcessed	prometheus.Counter
	notificationsProcessedErrors	prometheus.Counter
	filesProcessed			prometheus.Counter
	filesProcessedErrors	prometheus.Counter
	eventsProcessed			prometheus.Counter
	eventsProcessedErrors	prometheus.Counter
	info					prometheus.Gauge
	customCounterMetrics	[]customCounterMetric
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
	Subject				string	`json:",omitempty"`
	MessageID			string
	TopicArn			string
	Message				string
	Timestamp			string
	SignatureVersion	string
	Signature			string
	SigningCertURL		string
	UnsubscribeURL		string
}


// CloudTrail S3 Logfile specific information extracted from sqsMessage and sqsMessage.Message
type sqsNotificationMessage struct {
	S3Bucket		string		`json:"s3Bucket,omitempty"`
	S3ObjectKey		[]string	`json:"s3ObjectKey,omitempty"`
	Records         []messageObject `json:"Records,omitempty"`
	MessageID		string		`json:",omitempty"`
	ReceiptHandle	string		`json:",omitempty"`
}

type messageObject struct {
	EventTime		 string `json:"eventTime"`
	AwsRegion			string	`json:"awsRegion"`
	S3 struct {
		Bucket struct {
			Name		  string	  `json:"name"`
		} `json:"bucket"`
		Object		  struct {
			Key	   string `json:"key"`
		} `json:"object"`
	} `json:"s3"`
}

// Custom metrics will be stored in a list of structs
type customCounterMetric struct {
	Counter			prometheus.Counter
	Field			string
	Match			string
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

	logbeat.notificationsProcessed = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "s3_awslogs_beat_notifications",
			Help: "The total number of SQS notifications processed",
		})
	logbeat.notificationsProcessedErrors = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "s3_awslogs_beat_notifications_errors",
			Help: "The total number of errors ingesting SQS notifications",
		})

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
		logbeat.awsS3Config = &aws.Config{
			Credentials: credentials.NewSharedCredentials("", "logbeat.S3AwsLogBeatConfig.Input.AWSCredentialProvider"),
		}
		logbeat.awsSQSConfig = &aws.Config{
			Credentials: credentials.NewSharedCredentials("", "logbeat.S3AwsLogBeatConfig.Input.AWSCredentialProvider"),
		}
	} else {
		logbeat.awsS3Config = aws.NewConfig()
		logbeat.awsSQSConfig = aws.NewConfig()
	}

	if logbeat.S3AwsLogBeatConfig.Input.AWSRegion != nil {
		logbeat.awsS3Config = logbeat.awsS3Config.WithRegion(*logbeat.S3AwsLogBeatConfig.Input.AWSRegion)
		logbeat.awsSQSConfig = logbeat.awsSQSConfig.WithRegion(*logbeat.S3AwsLogBeatConfig.Input.AWSRegion)
	}

	// parse cmd line flags to determine if backfill or queue mode is being used
	if logbeat.CmdLineArgs.backfillBucket != nil {
		logbeat.backfillBucket = *logbeat.CmdLineArgs.backfillBucket

		if logbeat.CmdLineArgs.backfillPrefix != nil {
			logbeat.backfillPrefix = *logbeat.CmdLineArgs.backfillPrefix
		}
	}

	// Setup metrics for custom counters
	for i := 0; i < len(logbeat.S3AwsLogBeatConfig.Metrics.MatchCounters); i++ {
		logbeat.customCounterMetrics = append(
			logbeat.customCounterMetrics, 
			customCounterMetric{
				Field: *logbeat.S3AwsLogBeatConfig.Metrics.MatchCounters[i].Field,
				Match: *logbeat.S3AwsLogBeatConfig.Metrics.MatchCounters[i].Match,
				Counter: promauto.NewCounter(
					prometheus.CounterOpts{
						Name: fmt.Sprintf("s3_awslogs_%s", *logbeat.S3AwsLogBeatConfig.Metrics.MatchCounters[i].Name),
						Help: *logbeat.S3AwsLogBeatConfig.Metrics.MatchCounters[i].Help,
					}),
			})
		logbeat.customCounterMetrics[len(logbeat.customCounterMetrics)-1].Counter.Add(0)
	}
	logp.Info("match_counter metrics: %#v", logbeat.customCounterMetrics)

	// Setup metric for general daemon information
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
	logp.Debug("s3awslogbeat", "Events will be left in SQS when processed: %t", logbeat.noPurge)
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
			logbeat.notificationsProcessedErrors.Inc()
			break
		}

		if len(messages) == 0 {
			logp.Info("No new events to process, sleeping for %.0f seconds", logbeat.sleepTime.Seconds())
			time.Sleep(logbeat.sleepTime)
			continue
		}

		logp.Info("Fetched %d new events from SQS.", len(messages))
		logbeat.notificationsProcessed.Add(float64(len(messages)))

		// fetch and process each log file
		for _, m := range messages {
			switch logbeat.logMode {
			case "cloudtrail":
				logp.Info("Downloading and processing log file: s3://%s/%s", m.S3Bucket, m.S3ObjectKey)
				lf, err := logbeat.readCloudTrailLogfile(m)
				if err != nil {
					logbeat.filesProcessedErrors.Inc()
					logp.Err("Error reading log file [messageID: %s]: %s", m.MessageId, err)
					continue
				}
				logbeat.filesProcessed.Inc()
				
				logp.Info("Publishing events from : s3://%s/%s", m.S3Bucket, m.S3ObjectKey)
				if err := logbeat.publishCloudTrailEvents(lf); err != nil {
					logp.Err("Error publishing events [messageID: %s]: %s", m.MessageId, err)
					continue
				}
			case "vpcflowlog":
				for _, r := range m.Records {
					logp.Info("Downloading and processing log file: s3://%s/%s", r.S3.Bucket.Name, r.S3.Object.Key)
					lf, err := logbeat.readVpcFlowLogfile(r)
					if err != nil {
						logp.Err("Error reading log file [messageID: %s]: %s", m.MessageId, err)
						continue
					}
					logbeat.filesProcessed.Inc()

					if err := logbeat.publishVpcFlowLogEvents(lf); err != nil {
						logp.Err("Error publishing events [messageID: %s]: %s", m.MessageId, err)
						continue
					}
				}
			case "guardduty":
				for _, r := range m.Records {
					logp.Info("Downloading and processing log file: s3://%s/%s", r.S3.Bucket.Name, r.S3.Object.Key)
					lf, err := logbeat.readGuardDutyLogfile(r)
					if err != nil {
						logp.Err("Error reading log file [messageID: %s]: %s", m.MessageId, err)
						continue
					}
					logbeat.filesProcessed.Inc()

					if err := logbeat.publishGuardDutyEvents(lf); err != nil {
						logp.Err("Error publishing events [messageID: %s]: %s", m.MessageId, err)
						continue
					}
				}
			default:
				logp.Err("The logMode %s is not implemented.", logbeat.logMode)
			}

			if !logbeat.noPurge {
				if err := logbeat.deleteMessage(m); err != nil {
					logp.Err("Error deleting processed SQS event [messageID: %s]: %s", m.MessageId, err)
				}
			}
		}
	}

	return nil
}

func (logbeat *S3AwsLogBeat) runBackfill() error {
	logp.Info("Backfilling using S3 bucket: s3://%s/%s", logbeat.backfillBucket, logbeat.backfillPrefix)

	s := s3.New(session.New(logbeat.awsS3Config))
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
	body := sqsNotificationMessage{
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

	q := sqs.New(session.New(logbeat.awsSQSConfig))
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

func (logbeat *S3AwsLogBeat) fetchMessages() ([]sqsNotificationMessage, error) {
	var m []sqsNotificationMessage

	q := sqs.New(session.New(logbeat.awsSQSConfig))
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
		event := sqsNotificationMessage{}
		event.MessageID = tmsg.MessageID
		event.ReceiptHandle = *e.ReceiptHandle

		if err := json.Unmarshal([]byte(*e.Body), &tmsg); err != nil {
			return nil, fmt.Errorf("SQS message JSON parse error [id: %s]: %s", *e.MessageId, err.Error())
		}

		switch logbeat.logMode {
		case "cloudtrail":
			if tmsg.Message == "CloudTrail validation message." {
				if !logbeat.noPurge {
					if err := logbeat.deleteMessage(event); err != nil {
						return nil, fmt.Errorf("Error deleting 'validation message' [id: %s]: %s", tmsg.MessageID, err)
					}
				}
				continue
			}
		case "vpcflowlog":
			if (tmsg.Subject != "Amazon S3 Notification") {
				logp.Info("s3awslogbeat", "Skipping SQS Message with Subject: %s [id: %s]", tmsg.Subject, *e.MessageId)
				continue
			}
		case "guardduty":

		default:
			logp.Err("The logMode %s is not implemented.", logbeat.logMode)
		}

		if err := json.Unmarshal([]byte(tmsg.Message), &event); err != nil {
			return nil, fmt.Errorf("SQS body JSON parse error [id: %s]: %s", *e.MessageId, err.Error())
		}

		m = append(m, event)
	}

	return m, nil
}

func (logbeat *S3AwsLogBeat) deleteMessage(m sqsNotificationMessage) error {
	q := sqs.New(session.New(logbeat.awsSQSConfig))
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
