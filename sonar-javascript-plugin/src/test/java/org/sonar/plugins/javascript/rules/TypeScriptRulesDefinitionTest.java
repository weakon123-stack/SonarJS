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
package org.sonar.plugins.javascript.rules;

import com.google.gson.Gson;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.lang.annotation.Annotation;
import java.util.ArrayList;
import java.util.List;
import org.junit.Test;
import org.sonar.api.rules.RuleType;
import org.sonar.api.server.debt.DebtRemediationFunction.Type;
import org.sonar.api.server.rule.RulesDefinition;
import org.sonar.api.server.rule.RulesDefinition.Param;
import org.sonar.api.server.rule.RulesDefinition.Repository;
import org.sonar.api.server.rule.RulesDefinition.Rule;
import org.sonar.javascript.checks.CheckList;

import static org.assertj.core.api.Assertions.assertThat;

public class TypeScriptRulesDefinitionTest {

  private static final Gson gson = new Gson();

  @Test
  public void test() {
    Repository repository = buildRepository();

    assertThat(repository.name()).isEqualTo("SonarAnalyzer");
    assertThat(repository.language()).isEqualTo("ts");
    assertThat(repository.rules()).hasSize(CheckList.getTypeScriptChecks().size());

    assertRuleProperties(repository);
    assertAllRuleParametersHaveDescription(repository);
  }

  @Test
  public void sonarlint() {
    Repository repository = buildRepository();
    assertThat(repository.rule("S3923").activatedByDefault()).isTrue();
  }

  @Test
  public void compatibleLanguagesInJson() {
    List<Class> typeScriptChecks = CheckList.getTypeScriptChecks();
    List<Class> javaScriptChecks = CheckList.getJavaScriptChecks();
    CheckList.getAllChecks().forEach(c -> {
      boolean isTypeScriptCheck = typeScriptChecks.contains(c);
      boolean isJavaScriptCheck = javaScriptChecks.contains(c);
      Annotation ruleAnnotation = c.getAnnotation(org.sonar.check.Rule.class);
      String key = ((org.sonar.check.Rule) ruleAnnotation).key();

      RuleJson ruleJson = getRuleJson(key);
      assertThat(ruleJson.compatibleLanguages).as("For rule " + key).isNotNull().isNotEmpty();
      List<String> expected = new ArrayList<>();
      if (isTypeScriptCheck) {
        expected.add("TYPESCRIPT");
      }
      if (isJavaScriptCheck) {
        expected.add("JAVASCRIPT");
      }

      assertThat(ruleJson.compatibleLanguages).containsAll(expected);
    });
  }

  @Test
  public void sqKeyInJson() {
    CheckList.getAllChecks().forEach(c -> {
      Annotation ruleAnnotation = c.getAnnotation(org.sonar.check.Rule.class);
      String key = ((org.sonar.check.Rule) ruleAnnotation).key();
      RuleJson ruleJson = getRuleJson(key);
      assertThat(ruleJson.sqKey).isEqualTo(key);
    });
  }

  private static RuleJson getRuleJson(String key) {
    File file = new File(new File("../javascript-checks/src/main/resources", JavaScriptRulesDefinition.METADATA_LOCATION),
      key + ".json");
    try {
      return gson.fromJson(new FileReader(file), RuleJson.class);
    } catch (FileNotFoundException e) {
      throw new AssertionError("File for rule " + key + " is not found", e);
    }
  }

  private static class RuleJson {
    List<String> compatibleLanguages;
    String sqKey;
  }

  private Repository buildRepository() {
    TypeScriptRulesDefinition rulesDefinition = new TypeScriptRulesDefinition();
    RulesDefinition.Context context = new RulesDefinition.Context();
    rulesDefinition.define(context);
    Repository repository = context.repository("typescript");
    return repository;
  }

  private void assertRuleProperties(Repository repository) {
    Rule rule = repository.rule("S3923");
    assertThat(rule).isNotNull();
    assertThat(rule.name()).isEqualTo("All branches in a conditional structure should not have exactly the same implementation");
    assertThat(rule.debtRemediationFunction().type()).isEqualTo(Type.CONSTANT_ISSUE);
    assertThat(rule.type()).isEqualTo(RuleType.BUG);
    assertThat(repository.rule("S124").template()).isTrue();
  }

  private void assertAllRuleParametersHaveDescription(Repository repository) {
    for (Rule rule : repository.rules()) {
      for (Param param : rule.params()) {
        assertThat(param.description()).as("description for " + param.key()).isNotEmpty();
      }
    }
  }

}
