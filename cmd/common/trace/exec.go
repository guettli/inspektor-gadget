// Copyright 2022 The Inspektor Gadget authors
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

package trace

import (
	commonutils "github.com/kinvolk/inspektor-gadget/cmd/common/utils"
	"github.com/kinvolk/inspektor-gadget/pkg/gadgets/trace/exec/types"

	"github.com/spf13/cobra"
)

func NewExecCmd(runCmd func(*cobra.Command, []string) error) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "exec",
		Short: "Trace new processes",
		RunE:  runCmd,
	}
	commonutils.AddCobraOptions(cmd, types.MustGetColumns())
	return cmd
}
