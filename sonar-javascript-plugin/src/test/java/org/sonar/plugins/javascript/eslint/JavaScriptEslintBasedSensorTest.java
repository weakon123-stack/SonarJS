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
package org.sonar.plugins.javascript.eslint;

import com.google.gson.Gson;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Collection;
import java.util.Iterator;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.sonar.api.batch.fs.InputFile;
import org.sonar.api.batch.fs.InputFile.Type;
import org.sonar.api.batch.fs.internal.DefaultInputFile;
import org.sonar.api.batch.fs.internal.DefaultTextPointer;
import org.sonar.api.batch.fs.internal.DefaultTextRange;
import org.sonar.api.batch.fs.internal.TestInputFileBuilder;
import org.sonar.api.batch.rule.CheckFactory;
import org.sonar.api.batch.rule.internal.ActiveRulesBuilder;
import org.sonar.api.batch.rule.internal.NewActiveRule;
import org.sonar.api.batch.sensor.highlighting.TypeOfText;
import org.sonar.api.batch.sensor.internal.DefaultSensorDescriptor;
import org.sonar.api.batch.sensor.internal.SensorContextTester;
import org.sonar.api.batch.sensor.issue.Issue;
import org.sonar.api.batch.sensor.issue.IssueLocation;
import org.sonar.api.config.internal.MapSettings;
import org.sonar.api.internal.SonarRuntimeImpl;
import org.sonar.api.issue.NoSonarFilter;
import org.sonar.api.measures.CoreMetrics;
import org.sonar.api.measures.FileLinesContext;
import org.sonar.api.measures.FileLinesContextFactory;
import org.sonar.api.notifications.AnalysisWarnings;
import org.sonar.api.rule.RuleKey;
import org.sonar.api.utils.Version;
import org.sonar.api.utils.internal.JUnitTempFolder;
import org.sonar.api.utils.log.LogAndArguments;
import org.sonar.api.utils.log.LogTester;
import org.sonar.api.utils.log.LoggerLevel;
import org.sonar.javascript.checks.CheckList;
import org.sonar.plugins.javascript.JavaScriptSensor;
import org.sonar.plugins.javascript.eslint.EslintBridgeServer.AnalysisRequest;
import org.sonar.plugins.javascript.eslint.EslintBridgeServer.AnalysisResponse;
import org.sonarsource.nodejs.NodeCommandException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.clearInvocations;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class JavaScriptEslintBasedSensorTest {

  private static final String ESLINT_BASED_RULE = "S3923";

  @org.junit.Rule
  public LogTester logTester = new LogTester();

  @Mock
  private EslintBridgeServer eslintBridgeServerMock;

  @Mock
  private FileLinesContextFactory fileLinesContextFactory;

  @Rule
  public final ExpectedException thrown = ExpectedException.none();

  @Rule
  public JUnitTempFolder tempFolder = new JUnitTempFolder();
  private SensorContextTester context;

  @Before
  public void setUp() throws Exception {
    MockitoAnnotations.initMocks(this);
    when(eslintBridgeServerMock.isAlive()).thenReturn(true);
    when(eslintBridgeServerMock.analyzeJavaScript(any())).thenReturn(new AnalysisResponse());
    when(eslintBridgeServerMock.getCommandInfo()).thenReturn("eslintBridgeServerMock command info");
    context = SensorContextTester.create(tempFolder.newDir());

    FileLinesContext fileLinesContext = mock(FileLinesContext.class);
    when(fileLinesContextFactory.createFor(any(InputFile.class))).thenReturn(fileLinesContext);
  }

  @Test
  public void should_create_issues_from_eslint_based_rules() throws Exception {
    AnalysisResponse responseIssues = response("{ issues: [{" +
      "\"line\":1,\"column\":2,\"endLine\":3,\"endColumn\":4,\"ruleId\":\"no-all-duplicated-branches\",\"message\":\"Issue message\", \"secondaryLocations\": []}," +
      "{\"line\":1,\"column\":1,\"ruleId\":\"no-all-duplicated-branches\",\"message\":\"Line issue message\", \"secondaryLocations\": []}," +
      "{\"line\":0,\"column\":1,\"ruleId\":\"file-header\",\"message\":\"File issue message\", \"secondaryLocations\": []}" +
      "]}");
    when(eslintBridgeServerMock.analyzeJavaScript(any())).thenReturn(responseIssues);

    JavaScriptEslintBasedSensor sensor = createSensor();
    DefaultInputFile inputFile = createInputFile(context);

    sensor.execute(context);

    assertThat(context.allIssues()).hasSize(3);

    Iterator<Issue> issues = context.allIssues().iterator();
    Issue firstIssue = issues.next();
    Issue secondIssue = issues.next();
    Issue thirdIssue = issues.next();

    IssueLocation location = firstIssue.primaryLocation();
    assertThat(location.inputComponent()).isEqualTo(inputFile);
    assertThat(location.message()).isEqualTo("Issue message");
    assertThat(location.textRange()).isEqualTo(new DefaultTextRange(new DefaultTextPointer(1, 2), new DefaultTextPointer(3, 4)));

    location = secondIssue.primaryLocation();
    assertThat(location.inputComponent()).isEqualTo(inputFile);
    assertThat(location.message()).isEqualTo("Line issue message");
    assertThat(location.textRange()).isEqualTo(new DefaultTextRange(new DefaultTextPointer(1, 0), new DefaultTextPointer(1, 9)));

    location = thirdIssue.primaryLocation();
    assertThat(location.inputComponent()).isEqualTo(inputFile);
    assertThat(location.message()).isEqualTo("File issue message");
    assertThat(location.textRange()).isNull();

    assertThat(firstIssue.ruleKey().rule()).isEqualTo("S3923");
    assertThat(secondIssue.ruleKey().rule()).isEqualTo("S3923");
    assertThat(thirdIssue.ruleKey().rule()).isEqualTo("S1451");
  }

  private AnalysisResponse response(String json) {
    return new Gson().fromJson(json, AnalysisResponse.class);
  }


  @Test
  public void should_report_secondary_issue_locations_from_eslint_based_rules() throws Exception {
    when(eslintBridgeServerMock.analyzeJavaScript(any())).thenReturn(response(
      "{ issues: [{\"line\":1,\"column\":2,\"endLine\":3,\"endColumn\":4,\"ruleId\":\"no-all-duplicated-branches\",\"message\":\"Issue message\", " +
        "\"cost\": 14," +
        "\"secondaryLocations\": [" +
        "{ message: \"Secondary\", \"line\":2,\"column\":0,\"endLine\":2,\"endColumn\":3}," +
        "{ message: \"Secondary\", \"line\":3,\"column\":1,\"endLine\":3,\"endColumn\":4}" +
        "]}]}"));

    JavaScriptEslintBasedSensor sensor = createSensor();
    DefaultInputFile inputFile = createInputFile(context);

    sensor.execute(context);

    assertThat(context.allIssues()).hasSize(1);

    Iterator<Issue> issues = context.allIssues().iterator();
    Issue issue = issues.next();

    assertThat(issue.gap()).isEqualTo(14);

    assertThat(issue.flows()).hasSize(2);

    IssueLocation secondary1 = issue.flows().get(0).locations().get(0);
    assertThat(secondary1.inputComponent()).isEqualTo(inputFile);
    assertThat(secondary1.message()).isEqualTo("Secondary");
    assertThat(secondary1.textRange()).isEqualTo(new DefaultTextRange(new DefaultTextPointer(2, 0), new DefaultTextPointer(2, 3)));

    IssueLocation secondary2 = issue.flows().get(1).locations().get(0);
    assertThat(secondary2.inputComponent()).isEqualTo(inputFile);
    assertThat(secondary2.message()).isEqualTo("Secondary");
    assertThat(secondary2.textRange()).isEqualTo(new DefaultTextRange(new DefaultTextPointer(3, 1), new DefaultTextPointer(3, 4)));
  }

  @Test
  public void should_not_report_secondary_when_location_are_null() throws Exception {
    when(eslintBridgeServerMock.analyzeJavaScript(any())).thenReturn(response(
      "{ issues: [{\"line\":1,\"column\":3,\"endLine\":3,\"endColumn\":5,\"ruleId\":\"no-all-duplicated-branches\",\"message\":\"Issue message\", " +
        "\"secondaryLocations\": [" +
        "{ message: \"Secondary\", \"line\":2,\"column\":1,\"endLine\":null,\"endColumn\":4}" +
        "]}]}"));

    JavaScriptEslintBasedSensor sensor = createSensor();
    createInputFile(context);
    sensor.execute(context);

    assertThat(context.allIssues()).hasSize(1);

    Iterator<Issue> issues = context.allIssues().iterator();
    Issue issue = issues.next();

    assertThat(issue.flows()).hasSize(0);
  }

  @Test
  public void should_report_cost_from_eslint_based_rules() throws Exception {
    when(eslintBridgeServerMock.analyzeJavaScript(any())).thenReturn(response(
      "{ issues: [{\"line\":1,\"column\":2,\"endLine\":3,\"endColumn\":4,\"ruleId\":\"no-all-duplicated-branches\",\"message\":\"Issue message\", " +
        "\"cost\": 42," + "\"secondaryLocations\": []}]}"));

    JavaScriptEslintBasedSensor sensor = createSensor();
    DefaultInputFile inputFile = createInputFile(context);

    sensor.execute(context);

    assertThat(context.allIssues()).hasSize(1);

    Iterator<Issue> issues = context.allIssues().iterator();
    Issue issue = issues.next();

    IssueLocation location = issue.primaryLocation();
    assertThat(location.inputComponent()).isEqualTo(inputFile);
    assertThat(location.message()).isEqualTo("Issue message");
    assertThat(location.textRange()).isEqualTo(new DefaultTextRange(new DefaultTextPointer(1, 2), new DefaultTextPointer(3, 4)));

    assertThat(issue.gap()).isEqualTo(42);
    assertThat(issue.flows()).hasSize(0);
  }

  @Test
  public void should_create_metrics_from_eslint_based_rules() throws Exception {
    AnalysisResponse responseMetrics = response("{ metrics: {\"ncloc\":[1, 2, 3],\"commentLines\":[4, 5, 6],\"nosonarLines\":[7, 8, 9],\"executableLines\":[10, 11, 12],\"functions\":1,\"statements\":2,\"classes\":3,\"complexity\":4,\"cognitiveComplexity\":5} }");
    when(eslintBridgeServerMock.analyzeJavaScript(any())).thenReturn(responseMetrics);

    JavaScriptEslintBasedSensor sensor = createSensor();
    DefaultInputFile inputFile = createInputFile(context);

    sensor.execute(context);

    assertThat(context.measure(inputFile.key(), CoreMetrics.FUNCTIONS).value()).isEqualTo(1);
    assertThat(context.measure(inputFile.key(), CoreMetrics.STATEMENTS).value()).isEqualTo(2);
    assertThat(context.measure(inputFile.key(), CoreMetrics.CLASSES).value()).isEqualTo(3);
    assertThat(context.measure(inputFile.key(), CoreMetrics.NCLOC).value()).isEqualTo(3);
    assertThat(context.measure(inputFile.key(), CoreMetrics.COMMENT_LINES).value()).isEqualTo(3);
    assertThat(context.measure(inputFile.key(), CoreMetrics.COMPLEXITY).value()).isEqualTo(4);
    assertThat(context.measure(inputFile.key(), CoreMetrics.COGNITIVE_COMPLEXITY).value()).isEqualTo(5);
  }

  @Test
  public void should_create_highlights_from_eslint_based_rules() throws Exception {
    AnalysisResponse responseCpdTokens = response("{ highlights: [{\"location\": { \"startLine\":1,\"startCol\":0,\"endLine\":1,\"endCol\":4},\"textType\":\"KEYWORD\"},{\"location\": { \"startLine\":2,\"startCol\":1,\"endLine\":2,\"endCol\":5},\"textType\":\"CONSTANT\"}] }");
    when(eslintBridgeServerMock.analyzeJavaScript(any())).thenReturn(responseCpdTokens);

    JavaScriptEslintBasedSensor sensor = createSensor();
    DefaultInputFile inputFile = createInputFile(context);

    sensor.execute(context);

    assertThat(context.highlightingTypeAt(inputFile.key(), 1, 0)).isNotEmpty();
    assertThat(context.highlightingTypeAt(inputFile.key(), 1, 0).get(0)).isEqualTo(TypeOfText.KEYWORD);
    assertThat(context.highlightingTypeAt(inputFile.key(), 2, 1)).isNotEmpty();
    assertThat(context.highlightingTypeAt(inputFile.key(), 2, 1).get(0)).isEqualTo(TypeOfText.CONSTANT);
    assertThat(context.highlightingTypeAt(inputFile.key(), 3, 0)).isEmpty();
  }

  @Test
  public void should_create_cpd_from_eslint_based_rules() throws Exception {
    AnalysisResponse responseCpdTokens = response("{ cpdTokens: [{\"location\": { \"startLine\":1,\"startCol\":0,\"endLine\":1,\"endCol\":4},\"image\":\"LITERAL\"},{\"location\": { \"startLine\":2,\"startCol\":1,\"endLine\":2,\"endCol\":5},\"image\":\"if\"}] }");
    when(eslintBridgeServerMock.analyzeJavaScript(any())).thenReturn(responseCpdTokens);

    JavaScriptEslintBasedSensor sensor = createSensor();
    DefaultInputFile inputFile = createInputFile(context);

    sensor.execute(context);

    assertThat(context.cpdTokens(inputFile.key())).hasSize(2);
  }

  @Test
  public void should_catch_if_bridge_server_not_started() throws Exception {
    doThrow(new IllegalStateException("failed to start server")).when(eslintBridgeServerMock).startServerLazily(context);

    JavaScriptEslintBasedSensor sensor = createSensor();
    createInputFile(context);
    sensor.execute(context);

    assertThat(logTester.logs(LoggerLevel.ERROR)).contains("Failure during analysis, eslintBridgeServerMock command info");
    assertThat(context.allIssues()).isEmpty();
  }


  @Test
  public void should_not_explode_if_no_response() throws Exception {
    when(eslintBridgeServerMock.analyzeJavaScript(any())).thenThrow(new IOException("error"));
    JavaScriptEslintBasedSensor sensor = createSensor();
    DefaultInputFile inputFile = createInputFile(context);
    sensor.execute(context);

    assertThat(logTester.logs(LoggerLevel.ERROR)).contains("Failed to get response while analyzing " + inputFile.uri());
    assertThat(context.allIssues()).isEmpty();
  }

  @Test
  public void should_have_descriptor() throws Exception {
    DefaultSensorDescriptor descriptor = new DefaultSensorDescriptor();

    createSensor().describe(descriptor);
    assertThat(descriptor.name()).isEqualTo("JavaScript analysis");
    assertThat(descriptor.languages()).containsOnly("js");
    assertThat(descriptor.type()).isEqualTo(Type.MAIN);
  }

  @Test
  public void should_have_configured_rules() throws Exception {
    ActiveRulesBuilder builder = new ActiveRulesBuilder();
    builder.addRule(new NewActiveRule.Builder().setRuleKey(RuleKey.of(CheckList.JS_REPOSITORY_KEY, "S1192")).build());// no-duplicate-string, default config
    builder.addRule(new NewActiveRule.Builder().setRuleKey(RuleKey.of(CheckList.JS_REPOSITORY_KEY, "S1479")).setParam("maximum", "42").build());// max-switch-cases
    builder.addRule(new NewActiveRule.Builder().setRuleKey(RuleKey.of(CheckList.JS_REPOSITORY_KEY, "S3923")).build());// no-all-duplicated-branches, without config
    CheckFactory checkFactory = new CheckFactory(builder.build());

    JavaScriptEslintBasedSensor sensor = new JavaScriptEslintBasedSensor(
      checkFactory,
      new NoSonarFilter(),
      fileLinesContextFactory,
      eslintBridgeServerMock,
      null);

    EslintBridgeServer.Rule[] rules = sensor.rules;

    assertThat(rules).hasSize(3);

    assertThat(rules[0].key).isEqualTo("no-duplicate-string");
    assertThat(rules[0].configurations).containsExactly(3);

    assertThat(rules[1].key).isEqualTo("max-switch-cases");
    assertThat(rules[1].configurations).containsExactly(42);

    assertThat(rules[2].key).isEqualTo("no-all-duplicated-branches");
    assertThat(rules[2].configurations).isEmpty();
  }

  @Test
  public void handle_missing_node() throws Exception {
    doThrow(new NodeCommandException("Exception Message", new IOException())).when(eslintBridgeServerMock).startServerLazily(any());
    AnalysisWarnings analysisWarnings = mock(AnalysisWarnings.class);
    JavaScriptEslintBasedSensor javaScriptEslintBasedSensor = new JavaScriptEslintBasedSensor(checkFactory(ESLINT_BASED_RULE),
      new NoSonarFilter(),
      fileLinesContextFactory,
      eslintBridgeServerMock,
      analysisWarnings,
      mock(JavaScriptSensor.class));

    javaScriptEslintBasedSensor.execute(context);
    assertThat(logTester.logs(LoggerLevel.ERROR)).contains("Exception Message");
    verify(analysisWarnings).addUnique("JavaScript and/or TypeScript rules were not executed. Exception Message");
  }

  @Test
  public void log_debug_if_already_failed_server() throws Exception {
    doThrow(new ServerAlreadyFailedException()).when(eslintBridgeServerMock).startServerLazily(any());
    JavaScriptEslintBasedSensor javaScriptEslintBasedSensor = createSensor();
    javaScriptEslintBasedSensor.execute(context);

    assertThat(logTester.logs()).contains("Skipping start of eslint-bridge server due to the failure during first analysis",
      "Skipping execution of eslint-based rules due to the problems with eslint-bridge server");
  }

  @Test
  public void stop_analysis_if_server_is_not_responding() throws Exception {
    when(eslintBridgeServerMock.isAlive()).thenReturn(false);
    JavaScriptEslintBasedSensor javaScriptEslintBasedSensor = createSensor();
    createInputFile(context);
    javaScriptEslintBasedSensor.execute(context);
    final LogAndArguments logAndArguments = logTester.getLogs(LoggerLevel.ERROR).get(0);
    assertThat(logAndArguments.getFormattedMsg()).isEqualTo("Failure during analysis, eslintBridgeServerMock command info");
    assertThat(((IllegalStateException) logAndArguments.getArgs().get()[0]).getMessage()).isEqualTo("eslint-bridge server is not answering");
  }

  @Test
  public void should_raise_a_parsing_error() throws IOException {
    when(eslintBridgeServerMock.analyzeJavaScript(any()))
      .thenReturn(new Gson().fromJson("{ parsingError: { line: 3, message: \"Parse error message\", code: \"Parsing\"} }", AnalysisResponse.class));
    createInputFile(context);
    createSensor().execute(context);
    Collection<Issue> issues = context.allIssues();
    assertThat(issues).hasSize(1);
    Issue issue = issues.iterator().next();
    assertThat(issue.primaryLocation().textRange().start().line()).isEqualTo(3);
    assertThat(issue.primaryLocation().message()).isEqualTo("Parse error message");
    assertThat(context.allAnalysisErrors()).hasSize(1);
    assertThat(logTester.logs(LoggerLevel.ERROR)).contains("Failed to parse file [dir/file.js] at line 3: Parse error message");
  }

  @Test
  public void should_not_create_parsing_issue_when_no_rule() throws IOException {
    when(eslintBridgeServerMock.analyzeJavaScript(any()))
      .thenReturn(new Gson().fromJson("{ parsingError: { line: 3, message: \"Parse error message\", code: \"Parsing\"} }", AnalysisResponse.class));
    createInputFile(context);
    new JavaScriptEslintBasedSensor(checkFactory(ESLINT_BASED_RULE), new NoSonarFilter(), fileLinesContextFactory, eslintBridgeServerMock, null).execute(context);
    Collection<Issue> issues = context.allIssues();
    assertThat(issues).hasSize(0);
    assertThat(context.allAnalysisErrors()).hasSize(1);
    assertThat(logTester.logs(LoggerLevel.ERROR)).contains("Failed to parse file [dir/file.js] at line 3: Parse error message");
  }

  @Test
  public void should_send_content_on_sonarlint() throws Exception {
    SensorContextTester ctx = SensorContextTester.create(tempFolder.newDir());
    ctx.setRuntime(SonarRuntimeImpl.forSonarLint(Version.create(4, 4)));
    createInputFile(ctx);
    ArgumentCaptor<AnalysisRequest> captor = ArgumentCaptor.forClass(AnalysisRequest.class);
    createSensor().execute(ctx);
    verify(eslintBridgeServerMock).analyzeJavaScript(captor.capture());
    assertThat(captor.getValue().fileContent).isEqualTo("if (cond)\n" +
      "doFoo(); \n" +
      "else \n" +
      "doFoo();");

    clearInvocations(eslintBridgeServerMock);
    ctx = SensorContextTester.create(tempFolder.newDir());
    createInputFile(ctx);
    createSensor().execute(ctx);
    verify(eslintBridgeServerMock).analyzeJavaScript(captor.capture());
    assertThat(captor.getValue().fileContent).isNull();
  }

  @Test
  public void should_send_content_when_not_utf8() throws Exception {
    File baseDir = tempFolder.newDir();
    SensorContextTester ctx = SensorContextTester.create(baseDir);
    String content = "if (cond)\ndoFoo(); \nelse \ndoFoo();";
    DefaultInputFile inputFile = new TestInputFileBuilder("moduleKey", "dir/file.js")
      .setLanguage("js")
      .setCharset(StandardCharsets.ISO_8859_1)
      .setContents(content)
      .build();
    ctx.fileSystem().add(inputFile);

    ArgumentCaptor<AnalysisRequest> captor = ArgumentCaptor.forClass(AnalysisRequest.class);
    createSensor().execute(ctx);
    verify(eslintBridgeServerMock).analyzeJavaScript(captor.capture());
    assertThat(captor.getValue().fileContent).isEqualTo(content);
  }

  @Test
  public void should_fail_fast() throws Exception {
    when(eslintBridgeServerMock.analyzeJavaScript(any())).thenThrow(new IOException("error"));
    JavaScriptEslintBasedSensor sensor = createSensor();
    MapSettings settings = new MapSettings().setProperty("sonar.internal.analysis.failFast", true);
    context.setSettings(settings);
    DefaultInputFile inputFile = createInputFile(context);
    assertThatThrownBy(() -> sensor.execute(context))
      .isInstanceOf(IllegalStateException.class)
      .hasMessage("Analysis failed (\"sonar.internal.analysis.failFast\"=true)");
  }

  @Test
  public void should_fail_fast_with_nodecommandexception() throws Exception {
    doThrow(new NodeCommandException("error")).when(eslintBridgeServerMock).startServerLazily(any());
    JavaScriptEslintBasedSensor sensor = createSensor();
    MapSettings settings = new MapSettings().setProperty("sonar.internal.analysis.failFast", true);
    context.setSettings(settings);
    assertThatThrownBy(() -> sensor.execute(context))
      .isInstanceOf(IllegalStateException.class)
      .hasMessage("Analysis failed (\"sonar.internal.analysis.failFast\"=true)");
  }

  @Test
  public void should_run_old_frontend() throws Exception {
    DefaultInputFile inputFile = new TestInputFileBuilder("moduleKey", "dir/file.js")
      .setLanguage("js")
      .setCharset(StandardCharsets.UTF_8)
      .setContents("0123;")
      .build();
    context.fileSystem().add(inputFile);

    CheckFactory checkFactory = checkFactory("OctalNumber");
    NoSonarFilter noSonarFilter = new NoSonarFilter();
    JavaScriptSensor jsSensor = new JavaScriptSensor(checkFactory, context.fileSystem(), null, null);
    JavaScriptEslintBasedSensor sensor = new JavaScriptEslintBasedSensor(checkFactory, noSonarFilter, fileLinesContextFactory, eslintBridgeServerMock, jsSensor);
    sensor.execute(context);

    assertThat(context.allIssues()).hasSize(1);
    assertThat(context.allIssues()).extracting(i -> i.ruleKey().toString()).containsExactly("javascript:OctalNumber");
  }

  @Test
  public void stop_analysis_if_cancelled() throws Exception {
    JavaScriptEslintBasedSensor sensor = createSensor();
    createInputFile(context);
    context.setCancelled(true);
    sensor.execute(context);
    assertThat(logTester.logs(LoggerLevel.INFO)).contains("org.sonar.plugins.javascript.CancellationException: Analysis interrupted because the SensorContext is in cancelled state");
  }

  private static CheckFactory checkFactory(String... ruleKeys) {
    ActiveRulesBuilder builder = new ActiveRulesBuilder();
    for (String ruleKey : ruleKeys) {
      builder.addRule(new NewActiveRule.Builder().setRuleKey(RuleKey.of(CheckList.JS_REPOSITORY_KEY, ruleKey)).build());
    }
    return new CheckFactory(builder.build());
  }

  private static DefaultInputFile createInputFile(SensorContextTester context) {
    DefaultInputFile inputFile = new TestInputFileBuilder("moduleKey", "dir/file.js")
      .setLanguage("js")
      .setCharset(StandardCharsets.UTF_8)
      .setContents("if (cond)\ndoFoo(); \nelse \ndoFoo();")
      .build();
    context.fileSystem().add(inputFile);
    return inputFile;
  }


  private JavaScriptEslintBasedSensor createSensor() {
    return new JavaScriptEslintBasedSensor(checkFactory(ESLINT_BASED_RULE, "ParsingError", "S1451"), new NoSonarFilter(), fileLinesContextFactory, eslintBridgeServerMock, mock(JavaScriptSensor.class));
  }
}
