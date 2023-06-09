package beater

import (
	"fmt"
	"strings"
	"time"

	"github.com/elastic/beats/libbeat/common"
	"github.com/elastic/beats/libbeat/logp"
	"github.com/elastic/beats/libbeat/publisher"
)

// data struct matching the defined fields of a CloudTrail Record as
//  described in:
//  http://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-record-contents.html
type ecrScanningNotification struct {
	Version				string				`json:"version"`
	Id					string				`json:"id"`
	DetailType			string				`json:"detail-type"`
	Source				string				`json:"source"`
	Account				string				`json:"account"`
	Time				string				`json:"time"`
	Region				string				`json:"region"`
	Resources			[]string			`json:"resources"`
	Detail				ecrScanningNotificationDetail `json:"detail"`
	DetailUrl			string				`json:",omitempty"`
	MessageId			string				`json:",omitempty"`
	ReceiptHandle		string				`json:",omitempty"`
}
type ecrScanningNotificationDetail struct {
	ScanStatus			string				`json:"scan-status"`
	RepositoryName		string				`json:"repository-name"`
	ImageDigest			string				`json:"image-digest"`
	ImageTags			[]string			`json:"image-tags"`
	FindingSeverityCounts	ecrScanningNotificationDetailFindings	`json:"finding-severity-counts"`
}

type ecrScanningNotificationDetailFindings struct {
	Informational	uint64		`json:"INFORMATIONAL"`
	Low				uint64		`json:"LOW"`
	Medium			uint64		`json:"MEDIUM"`
	High			uint64		`json:"HIGH"`
	Critical		uint64		`json:"CRITICAL"`
	Undefined		uint64		`json:"UNDEFINED"`
}

type ecrScanningDetailFieldFunction func(e *ecrScanningNotification) interface{}

var ecrScanningNotificationField = map[string]ecrScanningDetailFieldFunction{
    "version": func(e *ecrScanningNotification) interface{} { return e.Version },
    "id": func(e *ecrScanningNotification) interface{} { return e.Id },
    "detail-type": func(e *ecrScanningNotification) interface{} { return e.DetailType },
    "source": func(e *ecrScanningNotification) interface{} { return e.Source },
    "account": func(e *ecrScanningNotification) interface{} { return e.Account },
    "time": func(e *ecrScanningNotification) interface{} { return e.Time },
    "region": func(e *ecrScanningNotification) interface{} { return e.Region },
    "resources": func(e *ecrScanningNotification) interface{} { return e.Resources },
    "detail": func(e *ecrScanningNotification) interface{} { return e.Detail },
}

func ecrScanningNotificationMatchPattern(event ecrScanningNotification, field string, search string) bool {
	if strings.Contains(field, ".") {
		parts := strings.SplitN(field, ".", 2)
		logp.Debug("s3awslogbeat", "need to find %s in event.%s[\"%s\"] (ID: %+v)\n", search, parts[0], parts[1], event.Id)
		if mapToSearch := ecrScanningNotificationField[parts[0]](&event); mapToSearch != nil {
			logp.Debug("s3awslogbeat", "mapToSearch: %+v\n", mapToSearch)
			if fieldToSearch := mapToSearch.(map[string]interface{})[parts[1]]; fieldToSearch != nil {
				logp.Debug("s3awslogbeat", "fieldToSearch: %+v\n", fieldToSearch)
				return strings.Contains(fieldToSearch.(string), search)
			}
		}
	} else {
		logp.Debug("s3awslogbeat", "need to find %s in event.%s (ID: %+v)\n", search, field, event.Id)
		if fieldToSearch := ecrScanningNotificationField[field](&event); fieldToSearch != nil {
			return strings.Contains(fieldToSearch.(string), search)
		}
	}
	return false
}

func (logbeat *S3AwsLogBeat) publishEcrScanningNotificationEvents(log ecrScanningNotification) error {

	events := make([]common.MapStr, 0, 1)

	timestamp, err := time.Parse(logTimeFormat, log.Time)

	if err != nil {
		logp.Err("Unable to parse EventTime : %s", log.Time)
	}

	for _, counter := range logbeat.customCounterMetrics {
		if ecrScanningNotificationMatchPattern(log, counter.Field, counter.Match) {
			counter.Counter.Inc()
		}
	}

	log.DetailUrl = fmt.Sprintf(
		"https://%s.console.aws.amazon.com/ecr/repositories/private/%s/%s/_/image/%s/scan-results",
		log.Region,
		log.Account,
		log.Detail.RepositoryName,
		log.Detail.ImageDigest,
	)

	le := common.MapStr{
		"@timestamp": common.Time(timestamp),
		"type":	   "ECR Image Scan",
		"ecrscanning": log,
	}

	events = append(events, le)

	if !logbeat.events.PublishEvents(events, publisher.Sync, publisher.Guaranteed) {
		logbeat.eventsProcessedErrors.Add(float64(len(events)))
		return fmt.Errorf("Error publishing events")
	}
	logbeat.eventsProcessed.Add(float64(len(events)))

	return nil
}
