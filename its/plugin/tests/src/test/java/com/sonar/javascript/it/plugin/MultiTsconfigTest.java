/*
 * SonarQube JavaScript Plugin
 * Copyright (C) 2012-2020 SonarSource SA
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
package com.sonar.javascript.it.plugin;

import com.sonar.orchestrator.Orchestrator;
import com.sonar.orchestrator.build.SonarScanner;
import java.io.File;
import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.Test;
import org.sonarqube.ws.Issues.Issue;

import static com.sonar.javascript.it.plugin.Tests.getIssues;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.tuple;

public class MultiTsconfigTest {

  @ClassRule
  public static final Orchestrator orchestrator = Tests.ORCHESTRATOR;

  private static final String PROJECT = "multi-tsconfig-test-project";
  private static final File PROJECT_DIR = TestUtils.projectDir(PROJECT);

  @BeforeClass
  public static void startServer() throws Exception {
    orchestrator.resetData();
  }

  @Test
  public void test() throws Exception {
    SonarScanner build = SonarScanner.create()
      .setProjectKey(PROJECT)
      .setSourceEncoding("UTF-8")
      .setSourceDirs(".")
      .setProjectDir(PROJECT_DIR)
      // setting inclusions like this will exclude tsconfig.json files, which is what we want to test
      .setProperty("sonar.inclusions", "**/*.ts");

    orchestrator.getServer().provisionProject(PROJECT, PROJECT);
    orchestrator.getServer().associateProjectToQualityProfile(PROJECT, "ts", "eslint-based-rules-profile");

    TestUtils.npmInstall(PROJECT_DIR);
    orchestrator.executeBuild(build);

    assertThat(getIssues(PROJECT)).extracting(Issue::getLine, Issue::getComponent).containsExactlyInAnyOrder(
      tuple(4,  "multi-tsconfig-test-project:src/bar/main.ts"),
      tuple(3, "multi-tsconfig-test-project:src/dir1/main.ts"),
      tuple(3, "multi-tsconfig-test-project:src/dir2/main.ts"),
      tuple(3, "multi-tsconfig-test-project:src/foo/main.ts")
    );
  }
}
