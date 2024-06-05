// Copyright 2023 The Archivista Contributors
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

package attestationcollection

import (
	"context"
	"encoding/json"

	"github.com/in-toto/archivista/ent"
	"github.com/in-toto/archivista/pkg/metadatastorage"
	"github.com/in-toto/go-witness/attestation/sarif"
)

const (
	Predicate = "https://openvex.dev/ns"
)

type ParsedSarif sarif.Attestor

func Parse(data []byte) (metadatastorage.Storer, error) {
	parsedSarif := ParsedSarif{}
	if err := json.Unmarshal(data, &parsedSarif); err != nil {
		return parsedSarif, err
	}

	return parsedSarif, nil
}

func (ps ParsedSarif) Store(ctx context.Context, tx *ent.Tx, stmtID int) error {
	sarif, err := tx.Sarif.Create().
		SetStatementID(stmtID).
		SetSarifFileName(ps.ReportFile).
		Save(ctx)
	if err != nil {
		return err
	}

	for _, r := range ps.Report.Runs {
		for _, ru := range r.Tool.Driver.Rules {
			if err := tx.SarifRule.Create().
				SetRuleName(ru.Name).
				SetRuleID(ru.ID).
				SetShortDescription(ru.ShortDescription.Text).
				Exec(ctx); err != nil {
				return err
			}
		}
	}

	return nil
}
