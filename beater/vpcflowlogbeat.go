package beater

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"
	"encoding/csv"
	"reflect"
	"io"
	"strconv"
    "compress/gzip"

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
)

const logTimeFormat = "2006-01-02T15:04:05Z"

// vpcflowlogbeat contains configuration options specific to the current
//  running instance as defined in cmd line arguments and the configuration
//  file.
type vpcFlowLogBeat struct {
	sqsURL			string
	awsConfig		*aws.Config
	numQueueFetch	int
	sleepTime		time.Duration
	noPurge			bool
	VFLbConfig		ConfigSettings
	events			publisher.Client
	done			chan struct{}
	csvFields		map[string]int
}

// SQS message extracted from raw sqs event Body
type sqsMessage struct {
	Type				string
	Subject				string
	MessageID			string
	TopicArn			string
	Message				string
	Timestamp			string
	SignatureVersion	string
	Signature			string
	SigningCertURL		string
	UnsubscribeURL		string
}

// VPC Flow Logs in S3 object found in this specific information extracted from sqsMessage and sqsMessage.Message
type vpcFlowLogMessage struct {
	Records [] vpcFlowLogMessageObject `json:"Records"`
	MessageID		string   `json:",omitempty"`
	ReceiptHandle	string   `json:",omitempty"`
}

type vpcFlowLogMessageObject struct {
	EventTime         string `json:"eventTime"`
	AwsRegion			string	`json:"awsRegion"`
	S3 struct {
		Bucket struct {
			Name          string      `json:"name"`
		} `json:"bucket"`
		Object          struct {
			Key       string `json:"key"`
		} `json:"object"`
	} `json:"s3"`
}

// data struct matching the defined fields of a vpcFlowLog Record as
//  described in:
//  https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs.html#flow-logs-fields
type vpcFlowLog struct {
	Records []vpcFlowLogEvent
}
type vpcFlowLogEvent struct {
	Version				string	`csv:"version"`
	AccountId			int64	`csv:"account-id"`
	InterfaceId			string	`csv:"interface-id"`
	SrcAddr				string	`csv:"srcaddr"`
	DstAddr				string	`csv:"dstaddr"`
	SrcPort				int64	`csv:"srcport"`
	DstPort				int64	`csv:"dstport"`
	Protocol			int64	`csv:"protocol"`
	Packets				int64	`csv:"packets"`
	Bytes				int64	`csv:"bytes"`
	Start				int64	`csv:"start"`
	End					int64	`csv:"end"`
	Action				string	`csv:"action"`
	LogStatus			string	`csv:"log-status"`
	VpcId				string	`csv:"vpc-id"`
	SubnetId			string	`csv:"subnet-id"`
	InstanceId			string	`csv:"instance-id"`
	TcpFlags			string	`csv:"tcp-flags"`
	Type				string	`csv:"type"`
	PktSrcAddr			string	`csv:"pkt-srcaddr"`
	PktDstAddr			string	`csv:"pkt-dstaddr"`
	Region				string	`csv:"region"`
	AzId				string	`csv:"az-id"`
	SublocationType		string	`csv:"sublocation-type"`
	SublocationId		string	`csv:"sublocation-id"`
	PktSrcAwsService	string	`csv:"pkt-src-aws-service"`
	PktDstAwsService	string	`csv:"pkg-dst-aws-service"`
	FlowDirection		string	`csv:"flow-direction"`
	TrafficPath			string	`csv:"traffic-path"`
}

func New() *vpcFlowLogBeat {
	vflb := &vpcFlowLogBeat{}
	vflb.csvFields = make(map[string]int)
	return vflb
}

func (vflb *vpcFlowLogBeat) Config(b *beat.Beat) error {
	if err := cfgfile.Read(&vflb.VFLbConfig, ""); err != nil {
		logp.Err("Error reading configuration file: %v", err)
		return err
	}

	//Validate and instantiate configuration file variables
	if vflb.VFLbConfig.Input.SQSUrl != nil {
		vflb.sqsURL = *vflb.VFLbConfig.Input.SQSUrl
	} else {
		return errors.New("Invalid SQS URL in configuration file")
	}

	if vflb.VFLbConfig.Input.NumQueueFetch != nil {
		vflb.numQueueFetch = *vflb.VFLbConfig.Input.NumQueueFetch
	} else {
		vflb.numQueueFetch = 1
	}

	if vflb.VFLbConfig.Input.SleepTime != nil {
		vflb.sleepTime = time.Duration(*vflb.VFLbConfig.Input.SleepTime) * time.Second
	} else {
		vflb.sleepTime = time.Minute * 5
	}

	if vflb.VFLbConfig.Input.NoPurge != nil {
		vflb.noPurge = *vflb.VFLbConfig.Input.NoPurge
	} else {
		vflb.noPurge = false
	}

	// use AWS credentials from configuration file if provided, fall back to ENV and ~/.aws/credentials
	if vflb.VFLbConfig.Input.AWSCredentialProvider != nil {
		vflb.awsConfig = &aws.Config{
			Credentials: credentials.NewSharedCredentials("", "vflb.VFLbConfig.Input.AWSCredentialProvider"),
		}
	} else {
		vflb.awsConfig = aws.NewConfig()
	}

	if vflb.VFLbConfig.Input.AWSRegion != nil {
		vflb.awsConfig = vflb.awsConfig.WithRegion(*vflb.VFLbConfig.Input.AWSRegion)
	}

	logp.Debug("vpcflowlogbeat", "Init vpcflowlogbeat")
	logp.Debug("vpcflowlogbeat", "SQS Url: %s", vflb.sqsURL)
	logp.Debug("vpcflowlogbeat", "Number of items to fetch from queue: %d", vflb.numQueueFetch)
	logp.Debug("vpcflowlogbeat", "Time to sleep when queue is empty: %.0f", vflb.sleepTime.Seconds())
	logp.Debug("vpcflowlogbeat", "Events will be deleted from SQS when processed: %t", vflb.noPurge)

	return nil
}

func (vflb *vpcFlowLogBeat) Setup(b *beat.Beat) error {
	vflb.events = b.Events
	vflb.done = make(chan struct{})
	return nil
}

func (vflb *vpcFlowLogBeat) Run(b *beat.Beat) error {
	logp.Info("Running in queue mode")
	if err := vflb.runQueue(); err != nil {
		return fmt.Errorf("Error processing queue: %s", err)
	}
	return nil
}

func (vflb *vpcFlowLogBeat) runQueue() error {
	for {
		select {
		case <-vflb.done:
			return nil
		default:
		}

		messages, err := vflb.fetchMessages()
		if err != nil {
			logp.Err("Error fetching messages from SQS: %v", err)
			break
		}

		if len(messages) == 0 {
			logp.Info("No new events to process, sleeping for %.0f seconds", vflb.sleepTime.Seconds())
			time.Sleep(vflb.sleepTime)
			continue
		}

		logp.Info("Fetched %d new VPC Flow Log files from SQS.", len(messages))
		// fetch and process each log file
		for _, m := range messages {
			for _, r := range m.Records {
				logp.Info("Downloading and processing log file: s3://%s/%s", r.S3.Bucket.Name, r.S3.Object.Key)
				lf, err := vflb.readLogfile(r)
				if err != nil {
					logp.Err("Error reading log file [id: %s]: %s", m.MessageID, err)
					continue
				}

				if err := vflb.publishEvents(lf); err != nil {
					logp.Err("Error publishing VPC Flow Log events [id: %s]: %s", m.MessageID, err)
					continue
				}
			}

			if !vflb.noPurge {
				if err := vflb.deleteMessage(m); err != nil {
					logp.Err("Error deleting processed SQS event [id: %s]: %s", m.MessageID, err)
				}
			}
		}
	}

	return nil
}

func (vflb *vpcFlowLogBeat) Stop() {
	close(vflb.done)
}

func (vflb *vpcFlowLogBeat) Cleanup(b *beat.Beat) error {
	return nil
}

func (vflb *vpcFlowLogBeat) publishEvents(vfl vpcFlowLog) error {
	if len(vfl.Records) < 1 {
		return nil
	}

	events := make([]common.MapStr, 0, len(vfl.Records))

	for _, vfle := range vfl.Records {
		timestamp := time.Unix(int64(vfle.End), 0)

		be := common.MapStr{
			"@timestamp": common.Time(timestamp),
			"type":	   "VpcFlowLog",
			"vpcflowlog": vfle,
		}

		events = append(events, be)
	}
	if !vflb.events.PublishEvents(events, publisher.Sync, publisher.Guaranteed) {
		return fmt.Errorf("Error publishing events")
	}

	return nil
}

func (vflb *vpcFlowLogBeat) readLogfile(m vpcFlowLogMessageObject) (vpcFlowLog, error) {
	events := vpcFlowLog{}

	vflb.awsConfig = vflb.awsConfig.WithRegion(m.AwsRegion)

	s := s3.New(session.New(vflb.awsConfig))
	q := s3.GetObjectInput{
		Bucket: aws.String(m.S3.Bucket.Name),
		Key:	aws.String(m.S3.Object.Key),
	}
	o, err := s.GetObject(&q)
	if err != nil {
		return events, err
	}

	gunzip, err := gzip.NewReader(o.Body)
	if err != nil {
		return events, fmt.Errorf("Error gunzipping %v", q)
	}

	logs := csv.NewReader(gunzip)
	logs.Comma = ' '

	headerRow, err := logs.Read()
	if err == io.EOF {
		return events, fmt.Errorf("Downloaded logfile doesn't have a first header row.")
	} else if err != nil {
		panic(err) // or handle it another way
	}

	vflb.createFieldMap(headerRow[:]...)

	for {
		row, err := logs.Read()
		if err == io.EOF {
			break
		} else if err != nil {
			panic(err) // or handle it another way
		}

		var event vpcFlowLogEvent

		version := vflb.getRowIndexValue("Version")
		if (version >= 0) { event.Version = row[version] }
		accountid := vflb.getRowIndexValue("AccountId")
		if (accountid >= 0) { event.AccountId, _ = strconv.ParseInt(row[version], 10, 64) }
		interfaceid := vflb.getRowIndexValue("InterfaceId")
		if (interfaceid >= 0) { event.InterfaceId = row[interfaceid] }
		srcaddr := vflb.getRowIndexValue("SrcAddr")
		if (srcaddr >= 0) { event.SrcAddr = row[srcaddr] }
		dstaddr := vflb.getRowIndexValue("DstAddr")
		if (dstaddr >= 0) { event.DstAddr = row[dstaddr] }
		srcport := vflb.getRowIndexValue("SrcPort")
		if (srcport >= 0) { event.SrcPort, _ = strconv.ParseInt(row[srcport], 10, 64) }
		dstport := vflb.getRowIndexValue("DstPort")
		if (dstport >= 0) { event.DstPort, _ = strconv.ParseInt(row[dstport], 10, 64) }
		protocol := vflb.getRowIndexValue("Protocol")
		if (protocol >= 0) { event.Protocol, _ = strconv.ParseInt(row[protocol], 10, 64) }
		packets := vflb.getRowIndexValue("Packets")
		if (packets >= 0) { event.Packets, _ = strconv.ParseInt(row[packets], 10, 64) }
		bytes := vflb.getRowIndexValue("Bytes")
		if (bytes >= 0) { event.Bytes, _ = strconv.ParseInt(row[bytes], 10, 64) }
		start := vflb.getRowIndexValue("Start")
		if (start >= 0) { event.Start, _ = strconv.ParseInt(row[start], 10, 64) }
		end := vflb.getRowIndexValue("End")
		if (end >= 0) { event.End, _ = strconv.ParseInt(row[end], 10, 64) }
		action := vflb.getRowIndexValue("Action")
		if (action >= 0) { event.Action = row[action] }
		logstatus := vflb.getRowIndexValue("LogStatus")
		if (logstatus >= 0) { event.LogStatus = row[logstatus] }
		vpcid := vflb.getRowIndexValue("VpcId")
		if (vpcid >= 0) { event.VpcId = row[vpcid] }
		subnetid := vflb.getRowIndexValue("SubnetId")
		if (subnetid >= 0) { event.SubnetId = row[subnetid] }
		instanceid := vflb.getRowIndexValue("InstanceId")
		if (instanceid >= 0) { event.InstanceId = row[instanceid] }
		tcpflags := vflb.getRowIndexValue("TcpFlags")
		if (tcpflags >= 0) { event.TcpFlags = row[tcpflags] }
		ftype := vflb.getRowIndexValue("Type")
		if (ftype >= 0) { event.Type = row[ftype] }
		pktsrcaddr := vflb.getRowIndexValue("PktSrcAddr")
		if (pktsrcaddr >= 0) { event.PktSrcAddr = row[pktsrcaddr] }
		pktdstaddr := vflb.getRowIndexValue("PktDstAddr")
		if (pktdstaddr >= 0) { event.PktDstAddr = row[pktdstaddr] }
		region := vflb.getRowIndexValue("Region")
		if (region >= 0) { event.Region = row[region] }
		azid := vflb.getRowIndexValue("AzId")
		if (azid >= 0) { event.AzId = row[azid] }
		sublocationtype := vflb.getRowIndexValue("SublocationType")
		if (sublocationtype >= 0) { event.SublocationType = row[sublocationtype] }
		sublocationid := vflb.getRowIndexValue("SublocationId")
		if (sublocationid >= 0) { event.SublocationId = row[sublocationid] }
		pktsrcawsservice := vflb.getRowIndexValue("PktSrcAwsService")
		if (pktsrcawsservice >= 0) { event.PktSrcAwsService = row[pktsrcawsservice] }
		pktdstawsservice := vflb.getRowIndexValue("PktDstAwsService")
		if (pktdstawsservice >= 0) { event.PktDstAwsService = row[pktdstawsservice] }
		flowdirection := vflb.getRowIndexValue("FlowDirection")
		if (flowdirection >= 0) { event.FlowDirection = row[flowdirection] }
		trafficpath := vflb.getRowIndexValue("TrafficPath")
		if (trafficpath >= 0) { event.TrafficPath = row[trafficpath] }

		logp.Debug("vpcflowlogbeat", "created event, %v", event)
		events.Records = append(events.Records, event)

		logp.Debug("vpcflowlogbeat", "appended event, %v", events)
	}

	return events, nil
}

func (vflb *vpcFlowLogBeat) getRowIndexValue(field string) (int) {
	var returnValue int = -1
	if index, ok := vflb.csvFields[field]; ok {
		returnValue = index
	}
	logp.Debug("vpcflowlogbeat", "getRowIndexValue %v yields %v", field, returnValue)
	return returnValue
}

func (vflb *vpcFlowLogBeat) createFieldMap(headerRow ...string) {

	var headerMap map[string]string = make(map[string]string)

	l := vpcFlowLogEvent{}
	lt := reflect.TypeOf(l)
	for i := 0; i < lt.NumField(); i++ {
		field := lt.Field(i)
		headerMap[field.Tag.Get("csv")] = field.Name
	}

	for i, h := range headerRow {
		vflb.csvFields[headerMap[h]] = i
	}
	logp.Debug("vpcflowlogbeat", "CSV Fields Parsed: %v", vflb.csvFields)
}

func (vflb *vpcFlowLogBeat) fetchMessages() ([]vpcFlowLogMessage, error) {
	var m []vpcFlowLogMessage

	q := sqs.New(session.New(vflb.awsConfig))
	params := &sqs.ReceiveMessageInput{
		QueueUrl:			aws.String(vflb.sqsURL),
		MaxNumberOfMessages: aws.Int64(int64(vflb.numQueueFetch)),
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
		logp.Debug("vpcflowlogbeat", "SQS Message received: %v", e)

		tmsg := sqsMessage{}
		if err := json.Unmarshal([]byte(*e.Body), &tmsg); err != nil {
			return nil, fmt.Errorf("SQS message JSON parse error [id: %s]: %s", *e.MessageId, err.Error())
		}
		logp.Debug("vpcflowlogbeat", "SQS Message parsed: %v", tmsg)

		if (tmsg.Subject != "Amazon S3 Notification") {
			logp.Info("vpcflowlogbeat", "Skipping SQS Message with Subject: %s [id: %s]", tmsg.Subject, *e.MessageId)
		}

		logp.Debug("vpcflowlogbeat", "SQS Message in a Message: %v", tmsg.Subject)
		logp.Debug("vpcflowlogbeat", "SQS Message in a Message: %v", tmsg.Message)
		event := vpcFlowLogMessage{}
		if err := json.Unmarshal([]byte(tmsg.Message), &event); err != nil {
			return nil, fmt.Errorf("SQS event parse error [id: %s]: %s", *e.MessageId, err.Error())
		}

		event.MessageID = tmsg.MessageID
		event.ReceiptHandle = *e.ReceiptHandle

		logp.Debug("vpcflowlogbeat", "SQS Message Event parsed: %v", event)

		m = append(m, event)
	}

	return m, nil
}

func (vflb *vpcFlowLogBeat) deleteMessage(m vpcFlowLogMessage) error {
	q := sqs.New(session.New(vflb.awsConfig))
	params := &sqs.DeleteMessageInput{
		QueueUrl:	  aws.String(vflb.sqsURL),
		ReceiptHandle: aws.String(m.ReceiptHandle),
	}

	_, err := q.DeleteMessage(params)
	if err != nil {
		return err
	}

	return nil
}
