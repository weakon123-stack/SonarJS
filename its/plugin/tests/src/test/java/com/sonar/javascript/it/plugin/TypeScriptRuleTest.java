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
import com.sonar.orchestrator.locator.FileLocation;
import com.sonar.orchestrator.locator.MavenLocation;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Collections;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import org.sonarsource.analyzer.commons.ProfileGenerator;

import static com.sonar.javascript.it.plugin.Tests.JAVASCRIPT_PLUGIN_LOCATION;
import static com.sonar.javascript.it.plugin.Tests.TS_PLUGIN_LOCATION;
import static org.assertj.core.api.Assertions.assertThat;

public class TypeScriptRuleTest {

  private static final String PROJECT_KEY = "ts-rule-project";
  private static final File PROJECT_DIR = TestUtils.projectDir(PROJECT_KEY);

  private static Orchestrator orchestrator;

  @BeforeClass
  public static void before() throws IOException, InterruptedException {
    orchestrator = Orchestrator.builderEnv()
      .setSonarVersion(System.getProperty("sonar.runtimeVersion", "LATEST_RELEASE"))
      .addPlugin(JAVASCRIPT_PLUGIN_LOCATION)
      .addPlugin(TS_PLUGIN_LOCATION)
      .addPlugin(MavenLocation.of("org.sonarsource.sonar-lits-plugin", "sonar-lits-plugin", "0.8.0.1209"))
      .build();

    orchestrator.start();

    File tsProfile = ProfileGenerator.generateProfile(
      orchestrator.getServer().getUrl(),
      "ts", "typescript",
      new ProfileGenerator.RulesConfiguration(),
      Collections.singleton("S124"));

    File jsProfile = ProfileGenerator.generateProfile(
      orchestrator.getServer().getUrl(),
      "js", "javascript",
      new ProfileGenerator.RulesConfiguration(),
      Collections.singleton("CommentRegularExpression"));

    orchestrator.getServer()
      .restoreProfile(FileLocation.of(jsProfile))
      .restoreProfile(FileLocation.of(tsProfile))
      .restoreProfile(FileLocation.ofClasspath("/ts-rules-project-profile.xml"))
      .restoreProfile(FileLocation.ofClasspath("/empty-js-profile.xml"));

    TestUtils.npmInstall(PROJECT_DIR);
  }

  @AfterClass
  public static void after() {
    orchestrator.stop();
  }


  @Test
  public void test() throws Exception {
    ExpectedIssues.parseForExpectedIssues(PROJECT_KEY, PROJECT_DIR.toPath());
    orchestrator.getServer().provisionProject(PROJECT_KEY, PROJECT_KEY);

    orchestrator.getServer().associateProjectToQualityProfile(PROJECT_KEY, "ts", "ts-rules-project-profile");
    orchestrator.getServer().associateProjectToQualityProfile(PROJECT_KEY, "js", "empty-profile");

    SonarScanner build = SonarScanner.create()
      .setProjectDir(PROJECT_DIR)
      .setProjectKey(PROJECT_KEY)
      .setSourceDirs(".")
      .setProperty("dump.old", FileLocation.of("target/expected/ts/" + PROJECT_KEY).getFile().getAbsolutePath())
      .setProperty("dump.new", FileLocation.of("target/actual/ts/" + PROJECT_KEY).getFile().getAbsolutePath())
      .setProperty("lits.differences", FileLocation.of("target/differences").getFile().getAbsolutePath())
      .setProperty("sonar.cpd.exclusions", "**/*");

    orchestrator.executeBuild(build);

    assertThat(new String(Files.readAllBytes(Paths.get("target/differences")), StandardCharsets.UTF_8)).isEmpty();
  }
}
