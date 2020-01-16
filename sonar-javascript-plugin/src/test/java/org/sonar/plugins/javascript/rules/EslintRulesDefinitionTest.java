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

import org.junit.Test;
import org.sonar.api.server.rule.RulesDefinition;
import org.sonar.api.server.rule.RulesDefinition.Repository;

import static org.assertj.core.api.Assertions.assertThat;

public class EslintRulesDefinitionTest {

  @Test
  public void should_create_external_repo() {
    EslintRulesDefinition eslintRulesDefinition = new EslintRulesDefinition();
    RulesDefinition.Context context = new RulesDefinition.Context();
    eslintRulesDefinition.define(context);
    assertThat(context.repositories()).hasSize(1);

    Repository eslintRepo = context.repository("external_eslint_repo");
    assertThat(eslintRepo.isExternal()).isTrue();
    assertThat(eslintRepo.name()).isEqualTo("ESLint");
    assertThat(eslintRepo.language()).isEqualTo("js");
    assertThat(eslintRepo.rules()).hasSize(607);

    // checking randoms rules from each ESLint plugin we support
    assertThat(eslintRepo.rule("angular/function-type")).isNotNull();
    assertThat(eslintRepo.rule(/*core*/ "no-useless-escape")).isNotNull();
    assertThat(eslintRepo.rule("ember/routes-segments-snake-case")).isNotNull();
    assertThat(eslintRepo.rule("flowtype/space-before-generic-bracket")).isNotNull();
    assertThat(eslintRepo.rule("import/order")).isNotNull();
    assertThat(eslintRepo.rule("jsx-a11y/anchor-is-valid")).isNotNull();
    assertThat(eslintRepo.rule("promise/no-return-wrap")).isNotNull();
    assertThat(eslintRepo.rule("react/no-find-dom-node")).isNotNull();
    assertThat(eslintRepo.rule("vue/v-on-style")).isNotNull();
    assertThat(eslintRepo.rule("sonarjs/no-duplicate-string")).isNotNull();
  }

}
