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
package org.sonar.plugins.javascript.lcov;

import com.google.common.base.Charsets;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.nio.charset.StandardCharsets;
import java.util.regex.Pattern;
import org.apache.commons.io.FileUtils;
import org.junit.Before;
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import org.sonar.api.batch.fs.InputFile;
import org.sonar.api.batch.fs.InputFile.Type;
import org.sonar.api.batch.fs.internal.DefaultInputFile;
import org.sonar.api.batch.fs.internal.FileMetadata;
import org.sonar.api.batch.fs.internal.TestInputFileBuilder;
import org.sonar.api.batch.sensor.internal.DefaultSensorDescriptor;
import org.sonar.api.batch.sensor.internal.SensorContextTester;
import org.sonar.api.config.internal.MapSettings;
import org.sonar.api.utils.log.LogTester;
import org.sonar.api.utils.log.LoggerLevel;
import org.sonar.plugins.javascript.JavaScriptPlugin;

import static org.assertj.core.api.Assertions.assertThat;

public class CoverageSensorTest {

  private static final String REPORT1 = "reports/report_1.lcov";
  private static final String REPORT2 = "reports/report_2.lcov";
  private static final String TWO_REPORTS = REPORT1 + ", " + REPORT2;

  private final String DEPRECATED_MESSAGE = "The use of sonar.typescript.lcov.reportPaths for coverage import is deprecated, use sonar.javascript.lcov.reportPaths instead.";
  private SensorContextTester context;
  private MapSettings settings;
  @ClassRule
  public static TemporaryFolder temp = new TemporaryFolder();

  private CoverageSensor coverageSensor = new CoverageSensor();
  private File moduleBaseDir = new File("src/test/resources/coverage/").getAbsoluteFile();

  @org.junit.Rule
  public LogTester logTester = new LogTester();

  @Before
  public void init() throws FileNotFoundException {
    settings = new MapSettings();

    context = SensorContextTester.create(moduleBaseDir);
    context.setSettings(settings);

    inputFile("file1.js", Type.MAIN);
    inputFile("file2.js", Type.MAIN);
    inputFile("tests/file1.js", Type.TEST);
  }

  private InputFile inputFile(String relativePath, Type type) throws FileNotFoundException {
    DefaultInputFile inputFile = new TestInputFileBuilder("moduleKey", relativePath)
      .setModuleBaseDir(moduleBaseDir.toPath())
      .setLanguage("js")
      .setType(type)
      .build();

    inputFile.setMetadata(new FileMetadata().readMetadata(new FileInputStream(inputFile.file()), Charsets.UTF_8, inputFile.absolutePath()));
    context.fileSystem().add(inputFile);

    return inputFile;
  }

  @Test
  public void report_not_found() throws Exception {
    settings.setProperty(JavaScriptPlugin.LCOV_REPORT_PATHS, "/fake/path/lcov_report.dat");

    coverageSensor.execute(context);

    // expected logged text: "No coverage information will be saved because all LCOV files cannot be found."
    assertThat(context.lineHits("moduleKey:file1.js", 1)).isNull();
  }

  @Test
  public void test_coverage() {
    settings.setProperty(JavaScriptPlugin.LCOV_REPORT_PATHS, TWO_REPORTS);
    coverageSensor.execute(context);
    assertTwoReportsCoverageDataPresent();
  }

  @Test
  public void should_work_and_log_warning_when_deprecated_key() throws Exception {
    settings.setProperty(JavaScriptPlugin.LCOV_REPORT_PATHS, "");
    settings.setProperty(JavaScriptPlugin.TS_LCOV_REPORT_PATHS, TWO_REPORTS);
    coverageSensor.execute(context);

    assertTwoReportsCoverageDataPresent();
    assertThat(logTester.logs(LoggerLevel.WARN)).contains(DEPRECATED_MESSAGE);
  }

  @Test
  public void should_include_coverage_from_both_key() throws Exception {
    settings.setProperty(JavaScriptPlugin.LCOV_REPORT_PATHS, REPORT1);
    settings.setProperty(JavaScriptPlugin.TS_LCOV_REPORT_PATHS, REPORT2);
    coverageSensor.execute(context);

    assertTwoReportsCoverageDataPresent();
    assertThat(logTester.logs(LoggerLevel.WARN)).contains(DEPRECATED_MESSAGE);
  }

  @Test
  public void both_properties_reports_paths_overlap() throws Exception {
    settings.setProperty(JavaScriptPlugin.LCOV_REPORT_PATHS, TWO_REPORTS);
    settings.setProperty(JavaScriptPlugin.TS_LCOV_REPORT_PATHS, TWO_REPORTS);
    coverageSensor.execute(context);

    assertTwoReportsCoverageDataPresent();
    assertThat(logTester.logs(LoggerLevel.WARN)).contains(DEPRECATED_MESSAGE);
  }

  private void assertTwoReportsCoverageDataPresent() {
    Integer[] file1Expected = {3, 3, 1, null};
    Integer[] file2Expected = {5, 5, null, null};

    for (int line = 1; line <= 4; line++) {
      assertThat(context.lineHits("moduleKey:file1.js", line)).isEqualTo(file1Expected[line - 1]);
      assertThat(context.lineHits("moduleKey:file2.js", line)).isEqualTo(file2Expected[line - 1]);
      assertThat(context.lineHits("moduleKey:file3.js", line)).isNull();
      assertThat(context.lineHits("moduleKey:tests/file1.js", line)).isNull();
    }

    assertThat(context.conditions("moduleKey:file1.js", 1)).isNull();
    assertThat(context.conditions("moduleKey:file1.js", 2)).isEqualTo(4);
    assertThat(context.coveredConditions("moduleKey:file1.js", 2)).isEqualTo(3);
  }

  @Test
  public void should_ignore_and_log_warning_for_invalid_line() {
    settings.setProperty(JavaScriptPlugin.LCOV_REPORT_PATHS, "reports/wrong_line_report.lcov");
    coverageSensor.execute(context);

    assertThat(context.lineHits("moduleKey:file1.js", 0)).isNull();
    assertThat(context.lineHits("moduleKey:file1.js", 2)).isEqualTo(1);

    assertThat(context.conditions("moduleKey:file1.js", 102)).isNull();
    assertThat(context.conditions("moduleKey:file1.js", 2)).isEqualTo(3);
    assertThat(context.coveredConditions("moduleKey:file1.js", 2)).isEqualTo(1);

    assertThat(logTester.logs()).contains("Problem during processing LCOV report: can't save DA data for line 3 of coverage report file (java.lang.IllegalArgumentException: Line with number 0 doesn't belong to file file1.js).");
    assertThat(logTester.logs()).contains("Problem during processing LCOV report: can't save BRDA data for line 8 of coverage report file (java.lang.IllegalArgumentException: Line with number 102 doesn't belong to file file1.js).");
  }

  @Test
  public void test_unresolved_path() {
    settings.setProperty(JavaScriptPlugin.LCOV_REPORT_PATHS, "reports/report_with_unresolved_path.lcov");
    coverageSensor.execute(context);

    // expected logged text: "Could not resolve 1 file paths in [...], first unresolved path: unresolved/file1.js"
    String fileName = File.separator + "reports" + File.separator + "report_with_unresolved_path.lcov";
    assertThat(logTester.logs()).contains("Could not resolve 1 file paths in [" + moduleBaseDir.getAbsolutePath() + fileName + "], first unresolved path: unresolved/file1.js");
  }

  @Test
  public void should_log_warning_when_wrong_data() throws Exception {
    settings.setProperty(JavaScriptPlugin.LCOV_REPORT_PATHS, "reports/wrong_data_report.lcov");
    coverageSensor.execute(context);

    assertThat(context.lineHits("moduleKey:file1.js", 1)).isNull();
    assertThat(context.lineHits("moduleKey:file1.js", 2)).isEqualTo(1);

    assertThat(context.conditions("moduleKey:file1.js", 2)).isEqualTo(2);
    assertThat(context.coveredConditions("moduleKey:file1.js", 2)).isEqualTo(2);

    assertThat(logTester.logs(LoggerLevel.DEBUG)).contains("Problem during processing LCOV report: can't save DA data for line 3 of coverage report file (java.lang.NumberFormatException: For input string: \"1.\").");
    // java.lang.StringIndexOutOfBoundsException may have different error message depending on JDK
    Pattern errorMessagePattern = Pattern.compile("Problem during processing LCOV report: can't save DA data for line 4 of coverage report file [(java.lang.StringIndexOutOfBoundsException: String index out of range: -1).|(java.lang.StringIndexOutOfBoundsException: begin 0, end -1, length 1).]");
    String stringIndexOutOfBoundLogMessage = logTester.logs(LoggerLevel.DEBUG).get(1);
    assertThat(stringIndexOutOfBoundLogMessage).containsPattern(errorMessagePattern);
    assertThat(logTester.logs(LoggerLevel.DEBUG).get(logTester.logs(LoggerLevel.DEBUG).size() - 1)).startsWith("Problem during processing LCOV report: can't save BRDA data for line 6 of coverage report file (java.lang.ArrayIndexOutOfBoundsException: ");
    assertThat(logTester.logs(LoggerLevel.WARN)).contains("Found 3 inconsistencies in coverage report. Re-run analyse in debug mode to see details.");
  }

  @Test
  public void should_contain_sensor_descriptor() {
    DefaultSensorDescriptor descriptor = new DefaultSensorDescriptor();

    coverageSensor.describe(descriptor);
    assertThat(descriptor.name()).isEqualTo("SonarJS Coverage");
    assertThat(descriptor.languages()).contains("js", "ts");
    assertThat(descriptor.type()).isEqualTo(Type.MAIN);
    assertThat(descriptor.configurationPredicate().test(new MapSettings().setProperty("sonar.javascript.lcov.reportPaths", "foo").asConfig())).isTrue();
    assertThat(descriptor.configurationPredicate().test(new MapSettings().setProperty("sonar.typescript.lcov.reportPaths", "foo").asConfig())).isTrue();
    assertThat(descriptor.configurationPredicate().test(new MapSettings().asConfig())).isFalse();
  }

  @Test
  public void should_resolve_relative_path() throws Exception {
    settings.setProperty(JavaScriptPlugin.LCOV_REPORT_PATHS, "reports/report_relative_path.lcov");
    inputFile("deep/nested/dir/js/file1.js", Type.MAIN);
    inputFile("deep/nested/dir/js/file2.js", Type.MAIN);
    coverageSensor.execute(context);

    String file1Key = "moduleKey:deep/nested/dir/js/file1.js";
    assertThat(context.lineHits(file1Key, 0)).isNull();
    assertThat(context.lineHits(file1Key, 1)).isEqualTo(2);
    assertThat(context.lineHits(file1Key, 2)).isEqualTo(2);

    assertThat(context.conditions(file1Key, 102)).isNull();
    assertThat(context.conditions(file1Key, 2)).isEqualTo(4);
    assertThat(context.coveredConditions(file1Key, 2)).isEqualTo(2);

    String file2Key = "moduleKey:deep/nested/dir/js/file2.js";
    assertThat(context.lineHits(file2Key, 0)).isNull();
    assertThat(context.lineHits(file2Key, 1)).isEqualTo(5);
    assertThat(context.lineHits(file2Key, 2)).isEqualTo(5);
  }

  @Test
  public void should_resolve_absolute_path() throws Exception {
    File lcovFile = temp.newFile();
    String absolutePathFile1 = new File("src/test/resources/coverage/file1.js").getAbsolutePath();
    String absolutePathFile2 = new File("src/test/resources/coverage/file2.js").getAbsolutePath();

    FileUtils.writeStringToFile(lcovFile, "SF:" + absolutePathFile1 + "\n" +
      "DA:1,2\n" +
      "DA:2,2\n" +
      "DA:3,1\n" +
      "FN:2,(anonymous_1)\n" +
      "FNDA:2,(anonymous_1)\n" +
      "BRDA:2,1,0,2\n" +
      "BRDA:2,1,1,1\n" +
      "BRDA:2,2,0,0\n" +
      "BRDA:2,2,1,-\n" +
      "end_of_record\n" +
      "SF:" + absolutePathFile2 + "\n" +
      "DA:1,5\n" +
      "DA:2,5\n" +
      "end_of_record\n", "UTF-8", false);
    settings.setProperty(JavaScriptPlugin.LCOV_REPORT_PATHS, lcovFile.getAbsolutePath());
    inputFile("file1.js", Type.MAIN);
    inputFile("file2.js", Type.MAIN);
    coverageSensor.execute(context);

    String file1Key = "moduleKey:file1.js";
    assertThat(context.lineHits(file1Key, 0)).isNull();
    assertThat(context.lineHits(file1Key, 1)).isEqualTo(2);
    assertThat(context.lineHits(file1Key, 2)).isEqualTo(2);

    assertThat(context.conditions(file1Key, 102)).isNull();
    assertThat(context.conditions(file1Key, 2)).isEqualTo(4);
    assertThat(context.coveredConditions(file1Key, 2)).isEqualTo(2);

    String file2Key = "moduleKey:file2.js";
    assertThat(context.lineHits(file2Key, 0)).isNull();
    assertThat(context.lineHits(file2Key, 1)).isEqualTo(5);
    assertThat(context.lineHits(file2Key, 2)).isEqualTo(5);
  }

  @Test
  public void should_import_coverage_for_ts() throws Exception {
    DefaultInputFile inputFile = new TestInputFileBuilder("moduleKey", "src/file1.ts")
      .setModuleBaseDir(moduleBaseDir.toPath())
      .setLanguage("ts")
      .setContents("function foo(x: any) {\n" +
        "  if (x && !x)\n" +
        "    console.log(\"file1\");\n" +
        "}\n")
      .build();
    context.fileSystem().add(inputFile);

    File lcov = temp.newFile();
    FileUtils.writeStringToFile(lcov, "SF:src/file1.ts\n" +
      "DA:1,2\n" +
      "DA:2,2\n" +
      "DA:3,1\n" +
      "FN:2,(anonymous_1)\n" +
      "FNDA:2,(anonymous_1)\n" +
      "BRDA:2,1,0,2\n" +
      "BRDA:2,1,1,1\n" +
      "BRDA:2,2,0,0\n" +
      "BRDA:2,2,1,-\n" +
      "end_of_record\n" +
      "SF:src/file2.ts\n" +
      "DA:1,5\n" +
      "DA:2,5\n" +
      "end_of_record\n", StandardCharsets.UTF_8);
    settings.setProperty(JavaScriptPlugin.LCOV_REPORT_PATHS, lcov.getAbsolutePath());
    coverageSensor.execute(context);
    assertThat(context.lineHits(inputFile.key(), 1)).isEqualTo(2);
    assertThat(context.lineHits(inputFile.key(), 2)).isEqualTo(2);
    assertThat(context.lineHits(inputFile.key(), 3)).isEqualTo(1);
    assertThat(context.lineHits(inputFile.key(), 0)).isNull();
  }

}
