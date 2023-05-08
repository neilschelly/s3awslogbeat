package beater

import (
	"fmt"
	"strings"
	"time"
	"encoding/csv"
	"io"
	"strconv"
	"compress/gzip"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"

	"github.com/elastic/beats/libbeat/common"
	"github.com/elastic/beats/libbeat/logp"
	"github.com/elastic/beats/libbeat/publisher"
)

// data struct matching the defined fields of a vpcFlowLog Record as
//  described in:
//  https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs.html#flow-logs-fields
type vpcFlowLog struct {
	Records []vpcFlowLogEvent
}
type vpcFlowLogEvent struct {
	EventTime		string	`json:"eventTime"`
	Ipv4SrcAddr		string	`json:"ipv4_src_addr"`
	Ipv6SrcAddr		string	`json:"ipv6_src_addr"`
	Ipv4DstAddr		string	`json:"ipv4_dst_addr"`
	Ipv6DstAddr		string	`json:"ipv6_dst_addr"`
	L4SrcPort		int64	`json:"l4_src_port"`
	L4DstPort		int64	`json:"l4_dst_port"`
	Protocol		int64	`json:"protocol"`
	InPkts			int64	`json:"in_pkts"`
	InBytes			int64	`json:"in_bytes"`
	Direction		int64	`json:"direction"`
	AwsDetails			struct {
		Version				string	`json:"version"`
		AccountId			int64	`json:"account_id"`
		InterfaceId			string	`json:"interface_id"`
		Start				int64	`json:"start"`
		End					int64	`json:"end"`
		Action				string	`json:"action"`
		LogStatus			string	`json:"log_status"`
		VpcId				string	`json:"vpc_id"`
		SubnetId			string	`json:"subnet_id"`
		InstanceId			string	`json:"instance_id"`
		TcpFlags			[]string	`json:"tcp_flags"`
		Type				string	`json:"type"`
		PktSrcAddr			string	`json:"pkg_src_addr"`
		PktDstAddr			string	`json:"pkg_dst_addr"`
		Region				string	`json:"region"`
		AzId				string	`json:"az_id"`
		SublocationType		string	`json:"sublocation_type"`
		SublocationId		string	`json:"sublocation_id"`
		PktSrcAwsService	string	`json:"pkt_src_aws_service"`
		PktDstAwsService	string	`json:"pkt_dst_aws_service"`
		FlowDirection		string	`json:"flow_direction"`
		TrafficPath			string	`json:"traffic_path"`
	}	`json:"aws_details"`
}

type vpcFlowLogEventFieldFunction func(e *vpcFlowLogEvent) interface{}

var vpcFlowLogEventField = map[string]vpcFlowLogEventFieldFunction{
    "eventTime": func(e *vpcFlowLogEvent) interface{}     { return e.EventTime },
    "ipv4_src_addr": func(e *vpcFlowLogEvent) interface{} { return e.Ipv4SrcAddr },
    "ipv6_src_addr": func(e *vpcFlowLogEvent) interface{} { return e.Ipv6SrcAddr },
    "ipv4_dst_addr": func(e *vpcFlowLogEvent) interface{} { return e.Ipv4DstAddr },
    "ipv6_dst_addr": func(e *vpcFlowLogEvent) interface{} { return e.Ipv6DstAddr },
    "l4_src_port": func(e *vpcFlowLogEvent) interface{}   { return e.L4SrcPort },
    "l4_dst_port": func(e *vpcFlowLogEvent) interface{}   { return e.L4DstPort },
    "protocol": func(e *vpcFlowLogEvent) interface{}      { return e.Protocol },
    "in_pkts": func(e *vpcFlowLogEvent) interface{}       { return e.InPkts },
    "in_bytes": func(e *vpcFlowLogEvent) interface{}      { return e.InBytes },
    "direction": func(e *vpcFlowLogEvent) interface{}     { return e.Direction },
    "aws_details": func(e *vpcFlowLogEvent) interface{}   { return e.AwsDetails },
}

func vpcFlowLogMatchPattern(event vpcFlowLogEvent, field string, search string) bool {
	if strings.Contains(field, ".") {
		parts := strings.SplitN(field, ".", 2)
		logp.Debug("s3awslogbeat", "need to find %s in event.%s[\"%s\"] (EventTime: %+v)\n", search, parts[0], parts[1], event.EventTime)
		if mapToSearch := vpcFlowLogEventField[parts[0]](&event); mapToSearch != nil {
			logp.Debug("s3awslogbeat", "mapToSearch: %+v\n", mapToSearch)
			if fieldToSearch := mapToSearch.(map[string]interface{})[parts[1]]; fieldToSearch != nil {
				logp.Debug("s3awslogbeat", "fieldToSearch: %+v\n", fieldToSearch)
				return strings.Contains(fieldToSearch.(string), search)
			}
		}
	} else {
		logp.Debug("s3awslogbeat", "need to find %s in event.%s (EventTime: %+v)\n", search, field, event.EventTime)
		if fieldToSearch := vpcFlowLogEventField[field](&event); fieldToSearch != nil {
			return strings.Contains(fieldToSearch.(string), search)
		}
	}
	return false
}

func (logbeat *S3AwsLogBeat) publishVpcFlowLogEvents(logs vpcFlowLog) error {
	if len(logs.Records) < 1 {
		return nil
	}

	events := make([]common.MapStr, 0, len(logs.Records))

	for _, logEvent := range logs.Records {
		timestamp, err := time.Parse(logTimeFormat, logEvent.EventTime)

		if err != nil {
			logp.Err("Unable to parse EventTime : %s", logEvent.EventTime)
		}

		for _, counter := range logbeat.customCounterMetrics {
			if vpcFlowLogMatchPattern(logEvent, counter.Field, counter.Match) {
				counter.Counter.Inc()
			}
		}

		le := common.MapStr{
			"@timestamp": common.Time(timestamp),
			"type":	   "VpcFlowLog",
			"netflow": logEvent,
			"ip_version": logEvent.AwsDetails.Type,
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

func (logbeat *S3AwsLogBeat) readVpcFlowLogfile(m vpcFlowLogMessageObject) (vpcFlowLog, error) {
	events := vpcFlowLog{}

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
		logp.Err("Unknown error reading header row from logfile: %v", err)
		panic(err) // or handle it another way
	}

	logbeat.createFieldMap(headerRow[:]...)

	logp.Info("Reading rows into VPCFlogLog events: s3://%s/%s", m.S3.Bucket.Name, m.S3.Object.Key)
	for {
		row, err := logs.Read()
		if err == io.EOF {
			break
		} else if err != nil {
			logp.Err("Unknown error reading row from logfile: %v", err)
			panic(err) // or handle it another way
		}

		for index, value := range row {
			if (value == "-") {
				row[index] = ""
			}
		}

		var event vpcFlowLogEvent

		/* A lot of the logic here is to mimic as much as possible the structure
		   of netflow data written into ELK by the netflow Logstash codec. AWS-
		   specific fields are all going to be in a sub-structure called
		   awsDetails */
		event.EventTime = m.EventTime
		version := logbeat.getRowIndexValue("version")
		if (version >= 0) { event.AwsDetails.Version = row[version] }
		accountid := logbeat.getRowIndexValue("account-id")
		if (accountid >= 0) { event.AwsDetails.AccountId, _ = strconv.ParseInt(row[accountid], 10, 64) }
		interfaceid := logbeat.getRowIndexValue("interface-id")
		if (interfaceid >= 0) { event.AwsDetails.InterfaceId = row[interfaceid] }
		ftype := logbeat.getRowIndexValue("type")
		if (ftype >= 0) { event.AwsDetails.Type = row[ftype] }
		srcaddr := logbeat.getRowIndexValue("srcaddr")
		dstaddr := logbeat.getRowIndexValue("dstaddr")
		if (event.AwsDetails.Type == "IPv4") {
			if (srcaddr >= 0) { event.Ipv4SrcAddr = row[srcaddr] }
			if (dstaddr >= 0) { event.Ipv4DstAddr = row[dstaddr] }
		} else if (event.AwsDetails.Type == "IPv6") {
			if (srcaddr >= 0) { event.Ipv6SrcAddr = row[srcaddr] }
			if (dstaddr >= 0) { event.Ipv6DstAddr = row[dstaddr] }
		}
		srcport := logbeat.getRowIndexValue("srcport")
		if (srcport >= 0) { event.L4SrcPort, _ = strconv.ParseInt(row[srcport], 10, 64) }
		dstport := logbeat.getRowIndexValue("dstport")
		if (dstport >= 0) { event.L4DstPort, _ = strconv.ParseInt(row[dstport], 10, 64) }
		protocol := logbeat.getRowIndexValue("protocol")
		if (protocol >= 0) { event.Protocol, _ = strconv.ParseInt(row[protocol], 10, 64) }
		packets := logbeat.getRowIndexValue("packets")
		if (packets >= 0) { event.InPkts, _ = strconv.ParseInt(row[packets], 10, 64) }
		bytes := logbeat.getRowIndexValue("bytes")
		if (bytes >= 0) { event.InBytes, _ = strconv.ParseInt(row[bytes], 10, 64) }
		start := logbeat.getRowIndexValue("start")
		if (start >= 0) { event.AwsDetails.Start, _ = strconv.ParseInt(row[start], 10, 64) }
		end := logbeat.getRowIndexValue("end")
		if (end >= 0) { event.AwsDetails.End, _ = strconv.ParseInt(row[end], 10, 64) }
		action := logbeat.getRowIndexValue("action")
		if (action >= 0) { event.AwsDetails.Action = row[action] }
		logstatus := logbeat.getRowIndexValue("log-status")
		if (logstatus >= 0) { event.AwsDetails.LogStatus = row[logstatus] }
		vpcid := logbeat.getRowIndexValue("vpc-id")
		if (vpcid >= 0) { event.AwsDetails.VpcId = row[vpcid] }
		subnetid := logbeat.getRowIndexValue("subnet-id")
		if (subnetid >= 0) { event.AwsDetails.SubnetId = row[subnetid] }
		instanceid := logbeat.getRowIndexValue("instance-id")
		if (instanceid >= 0) { event.AwsDetails.InstanceId = row[instanceid] }
		tcpflags := logbeat.getRowIndexValue("tcp-flags")
		if (tcpflags >= 0) {
			flags, _ := strconv.ParseInt(row[tcpflags], 10, 64)
			if ((flags & 1) == 1) {
				event.AwsDetails.TcpFlags = append(event.AwsDetails.TcpFlags, "FIN")
			}
			if ((flags & 2) == 2) {
				event.AwsDetails.TcpFlags = append(event.AwsDetails.TcpFlags, "SYN")
			}
			if ((flags & 18) == 18) {
				event.AwsDetails.TcpFlags = append(event.AwsDetails.TcpFlags, "SYN-ACK")
			}
			if ((flags & 4) == 4) {
				event.AwsDetails.TcpFlags = append(event.AwsDetails.TcpFlags, "RST")
			}
		}
		pktsrcaddr := logbeat.getRowIndexValue("pkt-srcaddr")
		if (pktsrcaddr >= 0) { event.AwsDetails.PktSrcAddr = row[pktsrcaddr] }
		pktdstaddr := logbeat.getRowIndexValue("pkt-dstaddr")
		if (pktdstaddr >= 0) { event.AwsDetails.PktDstAddr = row[pktdstaddr] }
		region := logbeat.getRowIndexValue("region")
		if (region >= 0) { event.AwsDetails.Region = row[region] }
		azid := logbeat.getRowIndexValue("az-id")
		if (azid >= 0) { event.AwsDetails.AzId = row[azid] }
		sublocationtype := logbeat.getRowIndexValue("sublocation-type")
		if (sublocationtype >= 0) { event.AwsDetails.SublocationType = row[sublocationtype] }
		sublocationid := logbeat.getRowIndexValue("sublocation-id")
		if (sublocationid >= 0) { event.AwsDetails.SublocationId = row[sublocationid] }
		pktsrcawsservice := logbeat.getRowIndexValue("pkt-src-aws-service")
		if (pktsrcawsservice >= 0) { event.AwsDetails.PktSrcAwsService = row[pktsrcawsservice] }
		pktdstawsservice := logbeat.getRowIndexValue("pkt-dst-aws-service")
		if (pktdstawsservice >= 0) { event.AwsDetails.PktDstAwsService = row[pktdstawsservice] }
		flowdirection := logbeat.getRowIndexValue("flow-direction")
		event.AwsDetails.FlowDirection = row[flowdirection]
		if (flowdirection >= 0) {
			if (row[flowdirection] == "ingress") {
				event.Direction = 0
			} else if (row[flowdirection] == "egress") {
				event.Direction = 1
			}
		}
		trafficpath := logbeat.getRowIndexValue("traffic-path")
		if (trafficpath >= 0) {
			switch row[trafficpath] {
			case "1":
				event.AwsDetails.TrafficPath = "1 — Through another resource in the same VPC"
			case "2":
				event.AwsDetails.TrafficPath = "2 — Through an internet gateway or a gateway VPC endpoint"
			case "3":
				event.AwsDetails.TrafficPath = "3 — Through a virtual private gateway"
			case "4":
				event.AwsDetails.TrafficPath = "4 — Through an intra-region VPC peering connection"
			case "5":
				event.AwsDetails.TrafficPath = "5 — Through an inter-region VPC peering connection"
			case "6":
				event.AwsDetails.TrafficPath = "6 — Through a local gateway"
			case "7":
				event.AwsDetails.TrafficPath = "7 — Through a gateway VPC endpoint (Nitro-based instances only)"
			case "8":
				event.AwsDetails.TrafficPath = "8 — Through an internet gateway (Nitro-based instances only)"
			}
		}

		logp.Debug("vpcflowlogbeat", "created event, %v", event)
		events.Records = append(events.Records, event)
	}
	logp.Info("Finished reading rows into VPCFlowLog events: s3://%s/%s", m.S3.Bucket.Name, m.S3.Object.Key)

	return events, nil
}

func (logbeat *S3AwsLogBeat) getRowIndexValue(field string) (int) {
	var returnValue int = -1
	if index, ok := logbeat.csvFields[field]; ok {
		returnValue = index
	}
	/* Too noisy even for debug mode
	logp.Debug("vpcflowlogbeat", "getRowIndexValue %v yields %v", field, returnValue) */
	return returnValue
}

func (logbeat *S3AwsLogBeat) createFieldMap(headerRow ...string) {
	logbeat.csvFields = make(map[string]int)
	for i, h := range headerRow {
		logbeat.csvFields[h] = i
	}
	logp.Debug("vpcflowlogbeat", "CSV Fields Parsed: %v", logbeat.csvFields)
}
