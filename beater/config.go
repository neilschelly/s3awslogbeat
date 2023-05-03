package beater

type S3AwsLogConfig struct {
	SQSUrl					*string `config:"sqs_url"`
	AWSCredentialProvider	*string `config:"aws_credential_provider"`
	AWSRegion				*string `config:"aws_region"`
	NoPurge					*bool   `config:"no_purge"`
	NumQueueFetch			*int    `config:"num_queue_fetch"`
	SleepTime				*int    `config:"sleep_time"`
	LogMode					*string `config:"log_mode"`
}

type MetricsConfig struct {
	MatchCounters			[]MatchCounter `config:"match_counters"`
}

type ConfigSettings struct {
	Input S3AwsLogConfig
	Metrics MetricsConfig
}

type MatchCounter struct {
	Name                  *string `config:"name"`
	Help                  *string `config:"help"`
	Field                 *string `config:"field"`
	Match                 *string `config:"match"`
}
