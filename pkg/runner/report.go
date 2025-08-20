package runner

import (
	"encoding/json"
	"log"
	"os"
	"strings"

	"github.com/chrizzn/fingerprintx/pkg/plugins"
)

type outputFormat string

const (
	JSON    outputFormat = "JSON"
	DEFAULT outputFormat = "DEFAULT"
)

func Report(services []plugins.Service) error {
	var writeFile *os.File
	var outputFormat = DEFAULT
	var err error

	log.SetFlags(0)

	if len(config.outputFile) > 0 {
		var fileErr error
		writeFile, fileErr = os.Create(config.outputFile)
		if fileErr != nil {
			return fileErr
		}
		log.SetOutput(writeFile)
	} else {
		log.SetOutput(os.Stdout)
	}
	defer writeFile.Close()

	if config.outputJSON {
		outputFormat = JSON
	}

	for _, service := range services {
		switch outputFormat {
		case JSON:
			data, jerr := json.Marshal(service)
			if jerr != nil {
				return err
			}
			log.Println(string(data))
		default:
			if len(service.Host) > 0 {
				log.Printf("%s://%s:%d (%s)\n", strings.ToLower(service.Protocol), service.Host, service.Port, service.IP)
			} else {
				log.Printf("%s://%s:%d\n", strings.ToLower(service.Protocol), service.IP, service.Port)
			}
		}
	}
	return nil
}
