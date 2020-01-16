/*
 * SonarQube JavaScript Plugin
 * Copyright (C) 2011-2020 SonarSource SA
 * mailto:info AT sonarsource DOT com
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 3 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */
package org.sonar.plugins.javascript.external;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.Objects;
import org.sonar.api.batch.fs.InputFile;
import org.sonar.api.batch.fs.TextRange;
import org.sonar.api.batch.sensor.SensorContext;
import org.sonar.api.batch.sensor.issue.NewExternalIssue;
import org.sonar.api.batch.sensor.issue.NewIssueLocation;
import org.sonar.api.utils.log.Logger;
import org.sonar.api.utils.log.Loggers;
import org.sonar.plugins.javascript.rules.TslintRulesDefinition;

import static org.sonar.plugins.javascript.JavaScriptPlugin.TSLINT_REPORT_PATHS;

public class TslintReportSensor extends AbstractExternalIssuesSensor {

  private static final Logger LOG = Loggers.get(TslintReportSensor.class);

  @Override
  String linterName() {
    return TslintRulesDefinition.LINTER_NAME;
  }

  @Override
  String reportsPropertyName() {
    return TSLINT_REPORT_PATHS;
  }

  @Override
  void importReport(File report, SensorContext context) {
    LOG.info("Importing {}", report.getAbsoluteFile());
    try (InputStreamReader inputStreamReader = new InputStreamReader(new FileInputStream(report), StandardCharsets.UTF_8)) {
      TslintError[] tslintErrors = gson.fromJson(inputStreamReader, TslintError[].class);
      for (TslintError tslintError : tslintErrors) {
        saveTslintError(context, tslintError);
      }
    } catch (IOException e) {
      LOG.error(FILE_EXCEPTION_MESSAGE, e);
    }
  }

  private void saveTslintError(SensorContext context, TslintError tslintError) {
    String tslintKey = tslintError.ruleName;

    InputFile inputFile = getInputFile(context, tslintError.name);
    if (inputFile == null) {
      return;
    }
    NewExternalIssue newExternalIssue = context.newExternalIssue();

    NewIssueLocation primaryLocation = newExternalIssue.newLocation()
      .message(tslintError.failure)
      .on(inputFile)
      .at(getLocation(tslintError, inputFile));

    newExternalIssue
      .at(primaryLocation)
      .engineId(TslintRulesDefinition.REPOSITORY_KEY)
      .ruleId(tslintKey)
      .type(TslintRulesDefinition.ruleType(tslintKey))
      .severity(DEFAULT_SEVERITY)
      .remediationEffortMinutes(DEFAULT_REMEDIATION_COST)
      .save();
  }

  private static TextRange getLocation(TslintError tslintError, InputFile inputFile) {
    if (tslintError.startPosition.equals(tslintError.endPosition)) {
      // tslint allows issue location with 0 length, SonarQube doesn't allow that
      return inputFile.selectLine(tslintError.startPosition.getOneBasedLine());
    } else {
      return inputFile.newRange(
        tslintError.startPosition.getOneBasedLine(),
        tslintError.startPosition.character,
        tslintError.endPosition.getOneBasedLine(),
        tslintError.endPosition.character);
    }
  }

  private static class TslintError {
    TslintPosition startPosition;
    TslintPosition endPosition;
    String failure;
    String name;
    String ruleName;
  }

  private static class TslintPosition {
    int character;
    int line;

    private int getOneBasedLine() {
      return line + 1;
    }

    @Override
    public boolean equals(Object obj) {
      if (this == obj) {
        return true;
      }
      if (obj == null || getClass() != obj.getClass()) {
        return false;
      }

      TslintPosition other = (TslintPosition) obj;
      return this.line == other.line && this.character == other.character;
    }

    @Override
    public int hashCode() {
      return Objects.hash(line, character);
    }
  }
}
