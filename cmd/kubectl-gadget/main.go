// Copyright 2019-2023 The Inspektor Gadget authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"fmt"
	"os"
	"strings"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	// Import this early to set the enrivonment variable before any other package is imported
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/environment/k8s"

	"github.com/inspektor-gadget/inspektor-gadget/cmd/common"
	commonutils "github.com/inspektor-gadget/inspektor-gadget/cmd/common/utils"
	"github.com/inspektor-gadget/inspektor-gadget/cmd/kubectl-gadget/advise"
	"github.com/inspektor-gadget/inspektor-gadget/cmd/kubectl-gadget/utils"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	grpcruntime "github.com/inspektor-gadget/inspektor-gadget/pkg/runtime/grpc"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/utils/experimental"

	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/all-gadgets"
	// The script is not included in the all gadgets package.
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/script"
)

var (
	grpcRuntime *grpcruntime.Runtime
	// common params for all gadgets
	params utils.CommonFlags
	deploy bool
)

var rootCmd = &cobra.Command{
	Use:   "kubectl-gadget",
	Short: "Collection of gadgets for Kubernetes developers",
}

var infoSkipCommands = []string{"deploy", "undeploy", "version"}

func init() {
	utils.FlagInit(rootCmd)
	rootCmd.PersistentFlags().BoolVar(&deploy, "deploy", false, "Deploy Inspektor Gadget to the cluster before running the gadget and undeploy it afterwards")
	addGeneralDeployFlags(rootCmd)
}

func main() {
	if experimental.Enabled() {
		log.Info("Experimental features enabled")
	}

	common.AddVerboseFlag(rootCmd)

	// grpcruntime.New() will try to fetch the info from the cluster by
	// default. Make sure we don't do this when certain commands are run
	// (as they just don't need it or imply that there are no nodes to
	// contact, yet).
	skipInfo := false
	for _, arg := range os.Args[1:] {
		for _, skipCmd := range infoSkipCommands {
			if strings.ToLower(arg) == skipCmd {
				skipInfo = true
			}
		}
	}

	// Remove the deploy flag from the help for "deploy", "version" and "undeploy"
	for _, c := range rootCmd.Commands() {
		switch c.Name() {
		case "deploy", "version", "undeploy":
			origHelp := c.HelpFunc()
			c.SetHelpFunc(func(cmd *cobra.Command, args []string) {
				c.InheritedFlags().MarkHidden("deploy")
				origHelp(cmd, args)
			})
		}
	}

	grpcRuntime = grpcruntime.New(grpcruntime.WithConnectUsingK8SProxy)
	runtimeGlobalParams := grpcRuntime.GlobalParamDescs().ToParams()
	common.AddFlags(rootCmd, runtimeGlobalParams, nil, grpcRuntime)
	grpcRuntime.Init(runtimeGlobalParams)
	if !skipInfo {
		// evaluate flags early for runtimeGlobalFlags; this will make
		// sure that --connection-method has already been parsed when calling
		// InitDeployInfo()

		err := commonutils.ParseEarlyFlags(rootCmd)
		if err != nil {
			// Analogous to cobra error message
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		grpcRuntime.InitDeployInfo()
	}

	namespace, _ := utils.GetNamespace()
	grpcRuntime.SetDefaultValue(gadgets.K8SNamespace, namespace)

	// Advise category is still being handled by CRs for now
	rootCmd.AddCommand(advise.NewAdviseCmd())

	rootCmd.AddCommand(common.NewSyncCommand(grpcRuntime))

	// Deploy and update our local registry before we add commands from it
	if deploy {
		err := runDeploy(os.Stderr)
		if err != nil {
			log.Errorf("deploying Inspektor Gadget: %v\n", err)
			os.Exit(1)
		}
		grpcRuntime.InitDeployInfo()
	}

	hiddenColumnTags := []string{"runtime"}
	common.AddCommandsFromRegistry(rootCmd, grpcRuntime, hiddenColumnTags)

	err := rootCmd.Execute()

	if deploy {
		err := runUndeploy(os.Stderr)
		if err != nil {
			log.Errorf("undeploying Inspektor Gadget: %v\n", err)
			os.Exit(1)
		}
	}

	if err != nil {
		os.Exit(1)
	}
}
