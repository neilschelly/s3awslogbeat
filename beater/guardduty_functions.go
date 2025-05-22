package beater

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
	"io"
	"bufio"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"

	"github.com/elastic/beats/libbeat/common"
	"github.com/elastic/beats/libbeat/logp"
	"github.com/elastic/beats/libbeat/publisher"
)

// data struct matching the defined fields of a GuardDuty Event as
// Unable to find a full JSON schema spec for this
type guarddutyLog struct {
	Records []guarddutyEvent
}
type guarddutyEvent struct {
	AccountID			string					`json:"accountId"`
	Region				string					`json:"region"`
	Partition			string					`json:"partition"`
	Arn					string					`json:"arn"`
	Type				string					`json:"type"`
	Resource			map[string]interface{}	`json:"resource"`
	Service				map[string]interface{}	`json:"service"`
	Severity			int64					`json:"severity"`
	CreatedAt			string					`json:"createdAt"`
	UpdatedAt			string					`json:"updatedAt"`
	Title				string					`json:"title"`
	Description			string					`json:"description"`
}

type guarddutyEventFieldFunction func(e *guarddutyEvent) interface{}

var guarddutyEventField = map[string]guarddutyEventFieldFunction{
    "accountID": func(e *guarddutyEvent) interface{}          { return e.AccountID },
    "region": func(e *guarddutyEvent) interface{}       { return e.Region },
    "partition": func(e *guarddutyEvent) interface{}        { return e.Partition },
    "arn": func(e *guarddutyEvent) interface{}       { return e.Arn },
    "type": func(e *guarddutyEvent) interface{}          { return e.Type },
    "resource": func(e *guarddutyEvent) interface{}          { return e.Resource },
    "service": func(e *guarddutyEvent) interface{}    { return e.Service },
    "severity": func(e *guarddutyEvent) interface{}          { return e.Severity },
    "createdAt": func(e *guarddutyEvent) interface{}          { return e.CreatedAt },
    "updatedAt": func(e *guarddutyEvent) interface{}       { return e.UpdatedAt },
    "title": func(e *guarddutyEvent) interface{}  { return e.Title },
    "description": func(e *guarddutyEvent) interface{}          { return e.Description },
}

func guarddutyMatchPattern(event guarddutyEvent, field string, search string) bool {
	if strings.Contains(field, ".") {
		parts := strings.SplitN(field, ".", 2)
		logp.Debug("s3awslogbeat", "need to find %s in event.%s[\"%s\"] (ARN: %+v)\n", search, parts[0], parts[1], event.Arn)
		if mapToSearch := guarddutyEventField[parts[0]](&event); mapToSearch != nil {
			logp.Debug("s3awslogbeat", "mapToSearch: %+v\n", mapToSearch)
			if fieldToSearch := mapToSearch.(map[string]interface{})[parts[1]]; fieldToSearch != nil {
				logp.Debug("s3awslogbeat", "fieldToSearch: %+v\n", fieldToSearch)
				return strings.Contains(fieldToSearch.(string), search)
			}
		}
	} else {
		logp.Debug("s3awslogbeat", "need to find %s in event.%s (ARN: %+v)\n", search, field, event.Arn)
		if fieldToSearch := guarddutyEventField[field](&event); fieldToSearch != nil {
			return strings.Contains(fieldToSearch.(string), search)
		}
	}
	return false
}

func guarddutyCheckUnusualField(event guarddutyEvent) guarddutyEvent {
	/*
	guardduty.service.additionalInfo.unusual is sometimes not there, sometimes
	a map, sometimes a number, and sometimes a string. The whole additionalInfo
	structure is unpredictable depending on the type of GuardDuty event it is.
	Here are some examples from generating sample findings:
	https://github.com/mozilla-services/foxsec-pipeline/blob/master/src/test/resources/testdata/gatekeeper/guardduty-sample-findings.txt

	The goal here is to make it more consistent for the benefit of Elasticsearch
	mapping and indexing.
	- If it is not there, pass the event unchanged.
	- If it is a map, pass the event unchanged.
	- If it is anything else, convert it to a map with "value" set to "VALUE"
	*/

	new_unusual := make(map[string]string)
	if service := guarddutyEventField["service"](&event); service != nil {
		if additionalInfo := service.(map[string]interface{})["additionalInfo"]; additionalInfo != nil {
			if unusual := additionalInfo.(map[string]interface{})["unusual"]; unusual != nil {
				if _, ok := unusual.(map[string]interface{}); ok {
					logp.Debug("s3awslogbeat", "guardduty.service.additionalInfo.unusual is a map already.")
					return event
				}
				if _, ok := unusual.(string); ok {
					logp.Debug("s3awslogbeat", "guardduty.service.additionalInfo.unusual is a string: %+v", unusual)
					new_unusual["value"] = unusual.(string)
				} else if _, ok := unusual.(float64); ok {
					logp.Debug("s3awslogbeat", "guardduty.service.additionalInfo.unusual is a number: %+v", unusual)
					new_unusual["value"] = fmt.Sprintf("%0.0f", unusual.(float64))
				}
				additionalInfo.(map[string]interface{})["unusual"] = new_unusual
			}
		}
	}

	return event
}

func (logbeat *S3AwsLogBeat) publishGuardDutyEvents(logs guarddutyLog) error {
	if len(logs.Records) < 1 {
		return nil
	}

	events := make([]common.MapStr, 0, len(logs.Records))
	var timestamp time.Time
	var err error

	for _, logEvent := range logs.Records {
		timestamp, err = time.Parse(logTimeFormat, logEvent.UpdatedAt)

		if err != nil {
			timestamp, err = time.Parse(logTimeFormat, logEvent.CreatedAt)
			if err != nil {
				logp.Err("Unable to parse CreatedAt : %s", logEvent.UpdatedAt)
			}
		}

		for _, counter := range logbeat.customCounterMetrics {
			if guarddutyMatchPattern(logEvent, counter.Field, counter.Match) {
				counter.Counter.Inc()
			}
		}

		logEvent = guarddutyCheckUnusualField(logEvent)

		le := common.MapStr{
			"@timestamp": common.Time(timestamp),
			"type":	   "GuardDuty",
			"guardduty": logEvent,
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

func (logbeat *S3AwsLogBeat) readGuardDutyLogfile(m messageObject) (guarddutyLog, error) {
	events := guarddutyLog{}

	logbeat.awsS3Config = logbeat.awsS3Config.WithRegion(m.AwsRegion)

	s := s3.New(session.New(logbeat.awsS3Config))
	q := s3.GetObjectInput{
		Bucket: aws.String(m.S3.Bucket.Name),
		Key:	aws.String(m.S3.Object.Key),
	}
	o, err := s.GetObject(&q)
	if err != nil {
		return events, err
	}

	b := bufio.NewReader(o.Body)
	logp.Info("Reading rows into GuardDuty events: s3://%s/%s", m.S3.Bucket.Name, m.S3.Object.Key)
	var lastLine bool
	lastLine = false
	for {
		var event guarddutyEvent
		jsonLine, err := b.ReadString('\n')
		if err == io.EOF {
			// last line of input
			lastLine = true
		}

		if err := json.Unmarshal([]byte(jsonLine), &event); err != nil {
			if len(jsonLine) == 0 && lastLine {
				// last line will be empty with newline
				logp.Debug("s3awslogbeat", "Last line of logfile is empty: %+v", err)
				break
			} else {
				logp.Info("Error unmarshaling guardduty JSON: %+v", err)
				logp.Info("%+v\n", jsonLine)
			}
		}

		logp.Debug("s3awslogbeat", "created event, %v", event)
		events.Records = append(events.Records, event)

		if lastLine {
			break
		}
	}
	logp.Info("Finished reading rows into GuardDuty events: s3://%s/%s", m.S3.Bucket.Name, m.S3.Object.Key)

	return events, nil
}
