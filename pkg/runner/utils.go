// Copyright 2022 Praetorian Security, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package runner

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/chrizzn/fingerprintx/pkg/scan"
)

func checkConfig(config cliConfig) error {
	if len(config.outputFile) > 0 {
		_, err := os.Stat(config.outputFile)
		if !os.IsNotExist(err) && config.overwriteOutput {
			fmt.Printf("File: %s already exists. Overwrite? [Y/N] ", config.outputFile)
			fmt.Scan(&userInput)
			if strings.ToLower(userInput)[0] != 'y' {
				return fmt.Errorf("Output file %s already exists", config.outputFile)
			}
		}
	}
	if config.outputJSON && config.outputCSV {
		return errors.New("Only one output format can be specified (JSON or CSV)")
	}

	if config.showErrors && !(config.outputJSON || config.outputCSV) {
		return errors.New("showErrors requires results being output in JSON or CSV format")
	}

	return nil
}

func createScanConfig(config cliConfig) scan.Config {
	return scan.Config{
		Ctx:            context.Background(),
		DefaultTimeout: time.Duration(config.timeout) * time.Millisecond,
		FastMode:       config.fastMode,
		FallBack:       config.fallBack,
		Verbose:        config.verbose,
	}
}
