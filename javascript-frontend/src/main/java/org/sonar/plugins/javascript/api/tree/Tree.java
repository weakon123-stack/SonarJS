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
package org.sonar.plugins.javascript.api.tree;

import com.google.common.annotations.Beta;
import java.util.stream.Stream;
import org.sonar.javascript.tree.impl.JavaScriptTree;
import org.sonar.plugins.javascript.api.tree.declaration.AccessorMethodDeclarationTree;
import org.sonar.plugins.javascript.api.tree.declaration.ArrayBindingPatternTree;
import org.sonar.plugins.javascript.api.tree.declaration.BindingPropertyTree;
import org.sonar.plugins.javascript.api.tree.declaration.ClassTree;
import org.sonar.plugins.javascript.api.tree.declaration.DecoratorTree;
import org.sonar.plugins.javascript.api.tree.declaration.DefaultExportDeclarationTree;
import org.sonar.plugins.javascript.api.tree.declaration.ExportClauseTree;
import org.sonar.plugins.javascript.api.tree.declaration.ExportDefaultBinding;
import org.sonar.plugins.javascript.api.tree.declaration.ExportDefaultBindingWithExportList;
import org.sonar.plugins.javascript.api.tree.declaration.ExportDefaultBindingWithNameSpaceExport;
import org.sonar.plugins.javascript.api.tree.declaration.ExtendsClauseTree;
import org.sonar.plugins.javascript.api.tree.declaration.FieldDeclarationTree;
import org.sonar.plugins.javascript.api.tree.declaration.FromClauseTree;
import org.sonar.plugins.javascript.api.tree.declaration.FunctionDeclarationTree;
import org.sonar.plugins.javascript.api.tree.declaration.ImportClauseTree;
import org.sonar.plugins.javascript.api.tree.declaration.ImportDeclarationTree;
import org.sonar.plugins.javascript.api.tree.declaration.ImportModuleDeclarationTree;
import org.sonar.plugins.javascript.api.tree.declaration.InitializedBindingElementTree;
import org.sonar.plugins.javascript.api.tree.declaration.MethodDeclarationTree;
import org.sonar.plugins.javascript.api.tree.declaration.NameSpaceExportDeclarationTree;
import org.sonar.plugins.javascript.api.tree.declaration.NameSpaceImportTree;
import org.sonar.plugins.javascript.api.tree.declaration.NamedExportDeclarationTree;
import org.sonar.plugins.javascript.api.tree.declaration.NamedImportExportClauseTree;
import org.sonar.plugins.javascript.api.tree.declaration.ObjectBindingPatternTree;
import org.sonar.plugins.javascript.api.tree.declaration.ParameterListTree;
import org.sonar.plugins.javascript.api.tree.declaration.SpecifierTree;
import org.sonar.plugins.javascript.api.tree.expression.ArrayAssignmentPatternTree;
import org.sonar.plugins.javascript.api.tree.expression.ArrayLiteralTree;
import org.sonar.plugins.javascript.api.tree.expression.ArrowFunctionTree;
import org.sonar.plugins.javascript.api.tree.expression.AssignmentExpressionTree;
import org.sonar.plugins.javascript.api.tree.expression.AssignmentPatternRestElementTree;
import org.sonar.plugins.javascript.api.tree.expression.BinaryExpressionTree;
import org.sonar.plugins.javascript.api.tree.expression.CallExpressionTree;
import org.sonar.plugins.javascript.api.tree.expression.ComputedPropertyNameTree;
import org.sonar.plugins.javascript.api.tree.expression.ConditionalExpressionTree;
import org.sonar.plugins.javascript.api.tree.expression.FunctionExpressionTree;
import org.sonar.plugins.javascript.api.tree.expression.IdentifierTree;
import org.sonar.plugins.javascript.api.tree.expression.ImportTree;
import org.sonar.plugins.javascript.api.tree.expression.InitializedAssignmentPatternElementTree;
import org.sonar.plugins.javascript.api.tree.expression.LiteralTree;
import org.sonar.plugins.javascript.api.tree.expression.MemberExpressionTree;
import org.sonar.plugins.javascript.api.tree.expression.NewExpressionTree;
import org.sonar.plugins.javascript.api.tree.expression.NewTargetTree;
import org.sonar.plugins.javascript.api.tree.expression.ObjectAssignmentPatternPairElementTree;
import org.sonar.plugins.javascript.api.tree.expression.ObjectAssignmentPatternTree;
import org.sonar.plugins.javascript.api.tree.expression.ObjectLiteralTree;
import org.sonar.plugins.javascript.api.tree.expression.PairPropertyTree;
import org.sonar.plugins.javascript.api.tree.expression.ParenthesisedExpressionTree;
import org.sonar.plugins.javascript.api.tree.expression.RestElementTree;
import org.sonar.plugins.javascript.api.tree.expression.SpreadElementTree;
import org.sonar.plugins.javascript.api.tree.expression.SuperTree;
import org.sonar.plugins.javascript.api.tree.expression.TaggedTemplateTree;
import org.sonar.plugins.javascript.api.tree.expression.TemplateCharactersTree;
import org.sonar.plugins.javascript.api.tree.expression.TemplateExpressionTree;
import org.sonar.plugins.javascript.api.tree.expression.TemplateLiteralTree;
import org.sonar.plugins.javascript.api.tree.expression.UnaryExpressionTree;
import org.sonar.plugins.javascript.api.tree.expression.YieldExpressionTree;
import org.sonar.plugins.javascript.api.tree.expression.jsx.JsxClosingElementTree;
import org.sonar.plugins.javascript.api.tree.expression.jsx.JsxEmptyClosingElementTree;
import org.sonar.plugins.javascript.api.tree.expression.jsx.JsxEmptyOpeningElementTree;
import org.sonar.plugins.javascript.api.tree.expression.jsx.JsxIdentifierTree;
import org.sonar.plugins.javascript.api.tree.expression.jsx.JsxJavaScriptExpressionTree;
import org.sonar.plugins.javascript.api.tree.expression.jsx.JsxOpeningElementTree;
import org.sonar.plugins.javascript.api.tree.expression.jsx.JsxSelfClosingElementTree;
import org.sonar.plugins.javascript.api.tree.expression.jsx.JsxShortFragmentElementTree;
import org.sonar.plugins.javascript.api.tree.expression.jsx.JsxSpreadAttributeTree;
import org.sonar.plugins.javascript.api.tree.expression.jsx.JsxStandardAttributeTree;
import org.sonar.plugins.javascript.api.tree.expression.jsx.JsxStandardElementTree;
import org.sonar.plugins.javascript.api.tree.expression.jsx.JsxTextTree;
import org.sonar.plugins.javascript.api.tree.flow.FlowArrayTypeShorthandTree;
import org.sonar.plugins.javascript.api.tree.flow.FlowArrayTypeTree;
import org.sonar.plugins.javascript.api.tree.flow.FlowCastingExpressionTree;
import org.sonar.plugins.javascript.api.tree.flow.FlowDeclareTree;
import org.sonar.plugins.javascript.api.tree.flow.FlowFunctionSignatureTree;
import org.sonar.plugins.javascript.api.tree.flow.FlowFunctionTypeParameterClauseTree;
import org.sonar.plugins.javascript.api.tree.flow.FlowFunctionTypeParameterTree;
import org.sonar.plugins.javascript.api.tree.flow.FlowFunctionTypeTree;
import org.sonar.plugins.javascript.api.tree.flow.FlowGenericParameterClauseTree;
import org.sonar.plugins.javascript.api.tree.flow.FlowGenericParameterTree;
import org.sonar.plugins.javascript.api.tree.flow.FlowImplementsClauseTree;
import org.sonar.plugins.javascript.api.tree.flow.FlowIndexerPropertyDefinitionKeyTree;
import org.sonar.plugins.javascript.api.tree.flow.FlowInterfaceDeclarationTree;
import org.sonar.plugins.javascript.api.tree.flow.FlowIntersectionTypeTree;
import org.sonar.plugins.javascript.api.tree.flow.FlowLiteralTypeTree;
import org.sonar.plugins.javascript.api.tree.flow.FlowMethodPropertyDefinitionKeyTree;
import org.sonar.plugins.javascript.api.tree.flow.FlowModuleExportsTree;
import org.sonar.plugins.javascript.api.tree.flow.FlowModuleTree;
import org.sonar.plugins.javascript.api.tree.flow.FlowNamespacedTypeTree;
import org.sonar.plugins.javascript.api.tree.flow.FlowObjectTypeTree;
import org.sonar.plugins.javascript.api.tree.flow.FlowOpaqueTypeTree;
import org.sonar.plugins.javascript.api.tree.flow.FlowOptionalBindingElementTree;
import org.sonar.plugins.javascript.api.tree.flow.FlowOptionalTypeTree;
import org.sonar.plugins.javascript.api.tree.flow.FlowParameterizedGenericsTypeTree;
import org.sonar.plugins.javascript.api.tree.flow.FlowParenthesisedTypeTree;
import org.sonar.plugins.javascript.api.tree.flow.FlowPropertyDefinitionTree;
import org.sonar.plugins.javascript.api.tree.flow.FlowSimplePropertyDefinitionKeyTree;
import org.sonar.plugins.javascript.api.tree.flow.FlowSimpleTypeTree;
import org.sonar.plugins.javascript.api.tree.flow.FlowTupleTypeTree;
import org.sonar.plugins.javascript.api.tree.flow.FlowTypeAliasStatementTree;
import org.sonar.plugins.javascript.api.tree.flow.FlowTypeAnnotationTree;
import org.sonar.plugins.javascript.api.tree.flow.FlowTypedBindingElementTree;
import org.sonar.plugins.javascript.api.tree.flow.FlowTypeofTypeTree;
import org.sonar.plugins.javascript.api.tree.flow.FlowUnionTypeTree;
import org.sonar.plugins.javascript.api.tree.lexical.SyntaxToken;
import org.sonar.plugins.javascript.api.tree.lexical.SyntaxTrivia;
import org.sonar.plugins.javascript.api.tree.statement.BlockTree;
import org.sonar.plugins.javascript.api.tree.statement.BreakStatementTree;
import org.sonar.plugins.javascript.api.tree.statement.CaseClauseTree;
import org.sonar.plugins.javascript.api.tree.statement.CatchBlockTree;
import org.sonar.plugins.javascript.api.tree.statement.ContinueStatementTree;
import org.sonar.plugins.javascript.api.tree.statement.DebuggerStatementTree;
import org.sonar.plugins.javascript.api.tree.statement.DefaultClauseTree;
import org.sonar.plugins.javascript.api.tree.statement.DoWhileStatementTree;
import org.sonar.plugins.javascript.api.tree.statement.ElseClauseTree;
import org.sonar.plugins.javascript.api.tree.statement.EmptyStatementTree;
import org.sonar.plugins.javascript.api.tree.statement.ExpressionStatementTree;
import org.sonar.plugins.javascript.api.tree.statement.FinallyBlockTree;
import org.sonar.plugins.javascript.api.tree.statement.ForObjectStatementTree;
import org.sonar.plugins.javascript.api.tree.statement.ForStatementTree;
import org.sonar.plugins.javascript.api.tree.statement.IfStatementTree;
import org.sonar.plugins.javascript.api.tree.statement.LabelledStatementTree;
import org.sonar.plugins.javascript.api.tree.statement.ReturnStatementTree;
import org.sonar.plugins.javascript.api.tree.statement.SwitchStatementTree;
import org.sonar.plugins.javascript.api.tree.statement.ThrowStatementTree;
import org.sonar.plugins.javascript.api.tree.statement.TryStatementTree;
import org.sonar.plugins.javascript.api.tree.statement.VariableDeclarationTree;
import org.sonar.plugins.javascript.api.tree.statement.VariableStatementTree;
import org.sonar.plugins.javascript.api.tree.statement.WhileStatementTree;
import org.sonar.plugins.javascript.api.tree.statement.WithStatementTree;
import org.sonar.plugins.javascript.api.visitors.DoubleDispatchVisitor;
import org.sonar.sslr.grammar.GrammarRuleKey;

/**
 * Common interface for all nodes in an abstract syntax tree.
 */
@Beta
public interface Tree {

  boolean is(Kinds... kind);

  SyntaxToken lastToken();

  SyntaxToken firstToken();

  void accept(DoubleDispatchVisitor visitor);

  boolean isAncestorOf(Tree tree);

  Stream<JavaScriptTree> descendants();

  Stream<Tree> childrenStream();

  Tree parent();

  public enum Kind implements GrammarRuleKey, Kinds {

    /**
     * {@link ScriptTree}
     */
    SCRIPT(ScriptTree.class),

    /**
     * {@link EmptyStatementTree}
     */
    EMPTY_STATEMENT(EmptyStatementTree.class),

    /**
     * {@link DebuggerStatementTree}
     */
    DEBUGGER_STATEMENT(DebuggerStatementTree.class),

    /**
     * {@link VariableStatementTree}
     */
    VARIABLE_STATEMENT(VariableStatementTree.class),

    /**
     * {@link VariableDeclarationTree}
     */
    VAR_DECLARATION(VariableDeclarationTree.class),

    /**
     * {@link VariableDeclarationTree}
     */
    LET_DECLARATION(VariableDeclarationTree.class),

    /**
     * {@link VariableDeclarationTree}
     */
    CONST_DECLARATION(VariableDeclarationTree.class),

    /**
     * {@link LabelledStatementTree}
     */
    LABELLED_STATEMENT(LabelledStatementTree.class),

    /**
     * {@link ContinueStatementTree}
     */
    CONTINUE_STATEMENT(ContinueStatementTree.class),

    /**
     * {@link BreakStatementTree}
     */
    BREAK_STATEMENT(BreakStatementTree.class),

    /**
     * {@link ReturnStatementTree}
     */
    RETURN_STATEMENT(ReturnStatementTree.class),

    /**
     * {@link ThrowStatementTree}
     */
    THROW_STATEMENT(ThrowStatementTree.class),

    /**
     * {@link WithStatementTree}
     */
    WITH_STATEMENT(WithStatementTree.class),

    /**
     * {@link BlockTree}
     */
    BLOCK(BlockTree.class),

    /**
     * {@link TryStatementTree}
     */
    TRY_STATEMENT(TryStatementTree.class),

    /**
     * {@link CatchBlockTree}
     */
    CATCH_BLOCK(CatchBlockTree.class),

    /**
     * {@link FinallyBlockTree}
     */
    FINALLY_BLOCK(FinallyBlockTree.class),

    /**
     * {@link SwitchStatementTree}
     */
    SWITCH_STATEMENT(SwitchStatementTree.class),

    /**
     * {@link CaseClauseTree}
     */
    CASE_CLAUSE(CaseClauseTree.class),

    /**
     * {@link DefaultClauseTree}
     */
    DEFAULT_CLAUSE(DefaultClauseTree.class),

    /**
     * {@link IfStatementTree}
     */
    IF_STATEMENT(IfStatementTree.class),

    /**
     * {@link ElseClauseTree}
     */
    ELSE_CLAUSE(ElseClauseTree.class),

    /**
     * {@link WhileStatementTree}
     */
    WHILE_STATEMENT(WhileStatementTree.class),

    /**
     * {@link DoWhileStatementTree}
     */
    DO_WHILE_STATEMENT(DoWhileStatementTree.class),

    /**
     * {@link ExpressionStatementTree}
     */
    EXPRESSION_STATEMENT(ExpressionStatementTree.class),

    /**
     * {@link ForObjectStatementTree}
     */
    FOR_OF_STATEMENT(ForObjectStatementTree.class),

    /**
     * {@link ForStatementTree}
     */
    FOR_STATEMENT(ForStatementTree.class),

    /**
     * {@link ForObjectStatementTree}
     */
    FOR_IN_STATEMENT(ForObjectStatementTree.class),

    /**
     * {@link IdentifierTree}
     * Used for identifiers referencing some symbol (variable, function, class, exported object)
     */
    IDENTIFIER_REFERENCE(IdentifierTree.class),

    /**
     * {@link IdentifierTree}
     * Used for identifiers which don't exist in any scope (e.g. object properties, exported and imported names)
     * Corresponds to <a href="https://tc39.github.io/ecma262/#prod-IdentifierName">IdentifierName</a> in ECMAScript Grammar
     */
    PROPERTY_IDENTIFIER(IdentifierTree.class),

    /**
     * {@link IdentifierTree}
     * Used for identifiers which create new variable existing in some scope (e.g. class/function names, exported names, variable declaration)
     */
    BINDING_IDENTIFIER(IdentifierTree.class),

    /**
     * {@link LiteralTree}
     * {@code null}
     */
    NULL_LITERAL(LiteralTree.class),

    /**
     * {@link LiteralTree}
     * {@code boolean}
     */
    BOOLEAN_LITERAL(LiteralTree.class),

    /**
     * {@link LiteralTree}
     * {@code numeric}
     */
    NUMERIC_LITERAL(LiteralTree.class),

    /**
     * {@link LiteralTree}
     * {@code string}
     */
    STRING_LITERAL(LiteralTree.class),

    /**
     * {@link LiteralTree}
     * {@code regexp}
     */
    REGULAR_EXPRESSION_LITERAL(LiteralTree.class),

    /**
     * {@link ArrayLiteralTree}
     */
    ARRAY_LITERAL(ArrayLiteralTree.class),

    /**
     * {@link ObjectLiteralTree}
     */
    OBJECT_LITERAL(ObjectLiteralTree.class),

    /**
     * {@link PairPropertyTree}
     */
    PAIR_PROPERTY(PairPropertyTree.class),

    /**
     * {@link org.sonar.plugins.javascript.api.tree.expression.FunctionExpressionTree}
     * {@code function * () {}}
     */
    GENERATOR_FUNCTION_EXPRESSION(FunctionExpressionTree.class),

    /**
     * {@link org.sonar.plugins.javascript.api.tree.expression.FunctionExpressionTree}
     * {@code function () {}}
     */
    FUNCTION_EXPRESSION(FunctionExpressionTree.class),

    /**
     * {@link ArrowFunctionTree}
     */
    ARROW_FUNCTION(ArrowFunctionTree.class),


    /**
     * {@link ParenthesisedExpressionTree}
     */
    PARENTHESISED_EXPRESSION(ParenthesisedExpressionTree.class),

    /**
     * {@link IdentifierTree}
     * {@code this}
     */
    THIS(IdentifierTree.class),

    /**
     * {@link LiteralTree}
     * {@code super}
     */
    SUPER(SuperTree.class),

    IMPORT(ImportTree.class),

    /**
     * {@link UnaryExpressionTree}
     * {@code ++}
     */
    POSTFIX_INCREMENT(UnaryExpressionTree.class),

    /**
     * {@link UnaryExpressionTree}
     * {@code --}
     */
    POSTFIX_DECREMENT(UnaryExpressionTree.class),

    /**
     * {@link UnaryExpressionTree}
     * {@code ++}
     */
    PREFIX_INCREMENT(UnaryExpressionTree.class),

    /**
     * {@link UnaryExpressionTree}
     * {@code --}
     */
    PREFIX_DECREMENT(UnaryExpressionTree.class),

    /**
     * {@link UnaryExpressionTree}
     * {@code +}
     */
    UNARY_PLUS(UnaryExpressionTree.class),

    /**
     * {@link UnaryExpressionTree}
     * {@code -}
     */
    UNARY_MINUS(UnaryExpressionTree.class),

    /**
     * {@link UnaryExpressionTree}
     * {@code ~}
     */
    BITWISE_COMPLEMENT(UnaryExpressionTree.class),

    /**
     * {@link UnaryExpressionTree}
     * {@code !}
     */
    LOGICAL_COMPLEMENT(UnaryExpressionTree.class),

    /**
     * {@link UnaryExpressionTree}
     * {@code delete}
     */
    DELETE(UnaryExpressionTree.class),

    /**
     * {@link UnaryExpressionTree}
     * {@code void}
     */
    VOID(UnaryExpressionTree.class),

    /**
     * {@link UnaryExpressionTree}
     * {@code typeof}
     */
    TYPEOF(UnaryExpressionTree.class),

    /**
     * {@link UnaryExpressionTree}
     * {@code await}
     */
    AWAIT(UnaryExpressionTree.class),

    /**
     * {@link BinaryExpressionTree}
     * {@code *}
     */
    MULTIPLY(BinaryExpressionTree.class),

    /**
     * {@link BinaryExpressionTree}
     * {@code **}
     */
    EXPONENT(BinaryExpressionTree.class),

    /**
     * {@link BinaryExpressionTree}
     * {@code /}
     */
    DIVIDE(BinaryExpressionTree.class),

    /**
     * {@link BinaryExpressionTree}
     * {@code %}
     */
    REMAINDER(BinaryExpressionTree.class),

    /**
     * {@link BinaryExpressionTree}
     * {@code +}
     */
    PLUS(BinaryExpressionTree.class),

    /**
     * {@link BinaryExpressionTree}
     * {@code -}
     */
    MINUS(BinaryExpressionTree.class),

    /**
     * {@link BinaryExpressionTree}
     * {@code <<}
     */
    LEFT_SHIFT(BinaryExpressionTree.class),

    /**
     * {@link BinaryExpressionTree}
     * {@code >>}
     */
    RIGHT_SHIFT(BinaryExpressionTree.class),

    /**
     * {@link BinaryExpressionTree}
     * {@code >>>}
     */
    UNSIGNED_RIGHT_SHIFT(BinaryExpressionTree.class),

    /**
     * {@link BinaryExpressionTree}
     */
    RELATIONAL_IN(BinaryExpressionTree.class),

    /**
     * {@link BinaryExpressionTree}
     */
    INSTANCE_OF(BinaryExpressionTree.class),

    /**
     * {@link BinaryExpressionTree}
     * {@code <}
     */
    LESS_THAN(BinaryExpressionTree.class),

    /**
     * {@link BinaryExpressionTree}
     * {@code >}
     */
    GREATER_THAN(BinaryExpressionTree.class),

    /**
     * {@link BinaryExpressionTree}
     * {@code <=}
     */
    LESS_THAN_OR_EQUAL_TO(BinaryExpressionTree.class),

    /**
     * {@link BinaryExpressionTree}
     * {@code >=}
     */
    GREATER_THAN_OR_EQUAL_TO(BinaryExpressionTree.class),

    /**
     * {@link BinaryExpressionTree}
     * {@code ==}
     */
    EQUAL_TO(BinaryExpressionTree.class),

    /**
     * {@link BinaryExpressionTree}
     * {@code ===}
     */
    STRICT_EQUAL_TO(BinaryExpressionTree.class),

    /**
     * {@link BinaryExpressionTree}
     * {@code !=}
     */
    NOT_EQUAL_TO(BinaryExpressionTree.class),

    /**
     * {@link BinaryExpressionTree}
     * {@code !==}
     */
    STRICT_NOT_EQUAL_TO(BinaryExpressionTree.class),

    /**
     * {@link BinaryExpressionTree}
     * {@code &}
     */
    BITWISE_AND(BinaryExpressionTree.class),

    /**
     * {@link BinaryExpressionTree}
     * {@code ^}
     */
    BITWISE_XOR(BinaryExpressionTree.class),

    /**
     * {@link BinaryExpressionTree}
     * {@code |}
     */
    BITWISE_OR(BinaryExpressionTree.class),

    /**
     * {@link BinaryExpressionTree}
     * {@code &&}
     */
    CONDITIONAL_AND(BinaryExpressionTree.class),

    /**
     * {@link BinaryExpressionTree}
     * {@code ||}
     */
    CONDITIONAL_OR(BinaryExpressionTree.class),

    /**
     * {@link BinaryExpressionTree}
     * {@code ,}
     */
    COMMA_OPERATOR(BinaryExpressionTree.class),

    /**
     * {@link ConditionalExpressionTree}
     */
    CONDITIONAL_EXPRESSION(ConditionalExpressionTree.class),

    /**
     * {@link AssignmentExpressionTree}
     * {@code =}
     */
    ASSIGNMENT(AssignmentExpressionTree.class),

    /**
     * {@link AssignmentExpressionTree}
     * {@code *=}
     */
    MULTIPLY_ASSIGNMENT(AssignmentExpressionTree.class),

    /**
     * {@link AssignmentExpressionTree}
     * {@code **=}
     */
    EXPONENT_ASSIGNMENT(AssignmentExpressionTree.class),

    /**
     * {@link AssignmentExpressionTree}
     * {@code /=}
     */
    DIVIDE_ASSIGNMENT(AssignmentExpressionTree.class),

    /**
     * {@link AssignmentExpressionTree}
     * {@code %=}
     */
    REMAINDER_ASSIGNMENT(AssignmentExpressionTree.class),

    /**
     * {@link AssignmentExpressionTree}
     * {@code +=}
     */
    PLUS_ASSIGNMENT(AssignmentExpressionTree.class),

    /**
     * {@link AssignmentExpressionTree}
     * {@code -=}
     */
    MINUS_ASSIGNMENT(AssignmentExpressionTree.class),

    /**
     * {@link AssignmentExpressionTree}
     * {@code <<=}
     */
    LEFT_SHIFT_ASSIGNMENT(AssignmentExpressionTree.class),

    /**
     * {@link AssignmentExpressionTree}
     * {@code >>=}
     */
    RIGHT_SHIFT_ASSIGNMENT(AssignmentExpressionTree.class),

    /**
     * {@link AssignmentExpressionTree}
     * {@code >>>=}
     */
    UNSIGNED_RIGHT_SHIFT_ASSIGNMENT(AssignmentExpressionTree.class),

    /**
     * {@link AssignmentExpressionTree}
     * {@code &=}
     */
    AND_ASSIGNMENT(AssignmentExpressionTree.class),

    /**
     * {@link AssignmentExpressionTree}
     * {@code ^=}
     */
    XOR_ASSIGNMENT(AssignmentExpressionTree.class),

    /**
     * {@link AssignmentExpressionTree}
     * {@code |=}
     */
    OR_ASSIGNMENT(AssignmentExpressionTree.class),

    /**
     * {@link NewExpressionTree}
     * {@code new expression}
     */
    NEW_EXPRESSION(NewExpressionTree.class),

    /**
     * {@link NewTargetTree}
     * {@code new expression}
     */
    NEW_TARGET(NewTargetTree.class),

    /**
     * {@link NewExpressionTree}
     */
    CALL_EXPRESSION(CallExpressionTree.class),

    /**
     * {@link NewExpressionTree}
     * {@code new super}
     */
    NEW_SUPER(NewExpressionTree.class),

    /**
     * {@link MemberExpressionTree}
     */
    DOT_MEMBER_EXPRESSION(MemberExpressionTree.class),

    /**
     * {@link MemberExpressionTree}
     */
    BRACKET_MEMBER_EXPRESSION(MemberExpressionTree.class),

    /**
     * {@link YieldExpressionTree}
     */
    YIELD_EXPRESSION(YieldExpressionTree.class),

    /**
     * {@link RestElementTree}
     */
    REST_ELEMENT(RestElementTree.class),

    /**
     * {@link SpreadElementTree}
     */
    SPREAD_ELEMENT(SpreadElementTree.class),

    /**
     * {@link FunctionDeclarationTree}
     */
    FUNCTION_DECLARATION(FunctionDeclarationTree.class),

    /**
     * {@link FunctionDeclarationTree}
     */
    GENERATOR_DECLARATION(FunctionDeclarationTree.class),

    /**
     * {@link ParameterListTree}
     */
    PARAMETER_LIST(ParameterListTree.class),

    /**
     * {@link TaggedTemplateTree}
     */
    TAGGED_TEMPLATE(TaggedTemplateTree.class),

    /**
     * {@link ParameterListTree}
     */
    ARGUMENT_LIST(ParameterListTree.class),

    /**
     * {@link ClassTree}
     */
    CLASS_EXPRESSION(ClassTree.class),

    /**
     * {@link ComputedPropertyNameTree}
     */
    COMPUTED_PROPERTY_NAME(ComputedPropertyNameTree.class),

    /**
     * {@link TemplateExpressionTree}
     */
    TEMPLATE_EXPRESSION(TemplateExpressionTree.class),

    /**
     * {@link TemplateLiteralTree}
     */
    TEMPLATE_LITERAL(TemplateLiteralTree.class),

    /**
     * {@link TemplateCharactersTree}
     */
    TEMPLATE_CHARACTERS(TemplateCharactersTree.class),

    /**
     * {@link AccessorMethodDeclarationTree}
     */
    SET_METHOD(AccessorMethodDeclarationTree.class),

    /**
     * {@link AccessorMethodDeclarationTree}
     */
    GET_METHOD(AccessorMethodDeclarationTree.class),

    /**
     * {@link MethodDeclarationTree}
     */
    GENERATOR_METHOD(MethodDeclarationTree.class),

    /**
     * {@link MethodDeclarationTree}
     */
    METHOD(MethodDeclarationTree.class),

    /**
     * {@link FieldDeclarationTree}
     */
    FIELD(FieldDeclarationTree.class),

    /**
     * {@link ClassTree}
     */
    CLASS_DECLARATION(ClassTree.class),

    /**
     * {@link ExtendsClauseTree}
     */
    EXTENDS_CLAUSE(ExtendsClauseTree.class),

    /**
     * {@link DecoratorTree}
     */
    DECORATOR(DecoratorTree.class),

    /**
     * {@link InitializedBindingElementTree}
     */
    INITIALIZED_BINDING_ELEMENT(InitializedBindingElementTree.class),

    /**
     * {@link ObjectBindingPatternTree}
     */
    OBJECT_BINDING_PATTERN(ObjectBindingPatternTree.class),

    /**
     * {@link BindingPropertyTree}
     */
    BINDING_PROPERTY(BindingPropertyTree.class),

    /**
     * {@link ArrayBindingPatternTree}
     */
    ARRAY_BINDING_PATTERN(ArrayBindingPatternTree.class),

    /**
     * {@link ArrayAssignmentPatternTree}
     */
    ARRAY_ASSIGNMENT_PATTERN(ArrayAssignmentPatternTree.class),

    /**
     * {@link ObjectAssignmentPatternTree}
     */
    OBJECT_ASSIGNMENT_PATTERN(ObjectAssignmentPatternTree.class),

    /**
     * {@link ObjectAssignmentPatternPairElementTree}
     */
    OBJECT_ASSIGNMENT_PATTERN_PAIR_ELEMENT(ObjectAssignmentPatternPairElementTree.class),

    /**
     * {@link InitializedAssignmentPatternElementTree}
     */
    INITIALIZED_ASSIGNMENT_PATTERN_ELEMENT(InitializedAssignmentPatternElementTree.class),

    /**
     * {@link AssignmentPatternRestElementTree}
     */
    ASSIGNMENT_PATTERN_REST_ELEMENT(AssignmentPatternRestElementTree.class),

    /**
     * {@link DefaultExportDeclarationTree}
     */
    DEFAULT_EXPORT_DECLARATION(DefaultExportDeclarationTree.class),

    /**
     * {@link NamedExportDeclarationTree}
     */
    NAMED_EXPORT_DECLARATION(NamedExportDeclarationTree.class),

    /**
     * {@link NameSpaceExportDeclarationTree}
     */
    NAMESPACE_EXPORT_DECLARATION(NameSpaceExportDeclarationTree.class),

    /**
     * {@link FromClauseTree}
     */
    FROM_CLAUSE(FromClauseTree.class),

    /**
     * {@link ExportClauseTree}
     */
    EXPORT_CLAUSE(ExportClauseTree.class),

    /**
     * {@link NamedImportExportClauseTree}
     */
    EXPORT_LIST(NamedImportExportClauseTree.class),

    /**
     * {@link ExportDefaultBinding}
     */
    EXPORT_DEFAULT_BINDING(ExportDefaultBinding.class),

    /**
     * {@link ExportDefaultBindingWithNameSpaceExport}
     */
    EXPORT_DEFAULT_BINDING_WITH_NAMESPACE_EXPORT(ExportDefaultBindingWithNameSpaceExport.class),

    /**
     * {@link ExportDefaultBindingWithExportList}
     */
    EXPORT_DEFAULT_BINDING_WITH_EXPORT_LIST(ExportDefaultBindingWithExportList.class),

    /**
     * {@link NamedImportExportClauseTree
     */
    IMPORT_LIST(NamedImportExportClauseTree.class),

    /**
     * {@link NamedImportExportClauseTree}
     */
    NAMED_IMPORTS(NamedImportExportClauseTree.class),

    /**
     * {@link SpecifierTree}
     */
    EXPORT_SPECIFIER(SpecifierTree.class),

    /**
     * {@link SpecifierTree}
     */
    IMPORT_SPECIFIER(SpecifierTree.class),

    /**
     * {@link NameSpaceImportTree}
     */
    NAME_SPACE_IMPORT(NameSpaceImportTree.class),

    /**
     * {@link ImportDeclarationTree}
     */
    IMPORT_DECLARATION(ImportDeclarationTree.class),

    /**
     * {@link ImportModuleDeclarationTree}
     */
    IMPORT_MODULE_DECLARATION(ImportModuleDeclarationTree.class),

    /**
     * {@link org.sonar.plugins.javascript.api.tree.ModuleTree}
     */
    MODULE(ModuleTree.class),

    /**
     * {@link ImportClauseTree}
     */
    IMPORT_CLAUSE(ImportClauseTree.class),

    /**
     * {@link JsxIdentifierTree}
     */
    JSX_IDENTIFIER(JsxIdentifierTree.class),

    /**
     * {@link JsxTextTree}
     */
    JSX_TEXT(JsxTextTree.class),

    /**
     * {@link JsxSpreadAttributeTree}
     */
    JSX_SPREAD_ATTRIBUTE(JsxSpreadAttributeTree.class),

    /**
     * {@link JsxStandardAttributeTree}
     */
    JSX_STANDARD_ATTRIBUTE(JsxStandardAttributeTree.class),

    /**
     * {@link JsxJavaScriptExpressionTree}
     */
    JSX_JAVASCRIPT_EXPRESSION(JsxJavaScriptExpressionTree.class),

    /**
     * {@link JsxOpeningElementTree}
     */
    JSX_OPENING_ELEMENT(JsxOpeningElementTree.class),

    /**
     * {@link JsxClosingElementTree}
     */
    JSX_CLOSING_ELEMENT(JsxClosingElementTree.class),

    /**
     * {@link JsxStandardElementTree}
     */
    JSX_STANDARD_ELEMENT(JsxStandardElementTree.class),

    /**
     * {@link JsxEmptyOpeningElementTree}
     */
    JSX_EMPTY_OPENING_ELEMENT(JsxEmptyOpeningElementTree.class),

    /**
     * {@link JsxEmptyClosingElementTree}
     */
    JSX_EMPTY_CLOSING_ELEMENT(JsxEmptyClosingElementTree.class),

    /**
     * {@link JsxShortFragmentElementTree}
     */
    JSX_SHORT_FRAGMENT_ELEMENT(JsxShortFragmentElementTree.class),

    /**
     * {@link JsxSelfClosingElementTree}
     */
    JSX_SELF_CLOSING_ELEMENT(JsxSelfClosingElementTree.class),

    FLOW_SIMPLE_TYPE(FlowSimpleTypeTree.class),
    FLOW_OPTIONAL_TYPE(FlowOptionalTypeTree.class),
    FLOW_UNION_TYPE(FlowUnionTypeTree.class),
    FLOW_INTERSECTION_TYPE(FlowIntersectionTypeTree.class),
    FLOW_LITERAL_TYPE(FlowLiteralTypeTree.class),
    FLOW_FUNCTION_TYPE(FlowFunctionTypeTree.class),
    FLOW_FUNCTION_TYPE_PARAMETER_CLAUSE(FlowFunctionTypeParameterClauseTree.class),
    FLOW_FUNCTION_TYPE_PARAMETER(FlowFunctionTypeParameterTree.class),
    FLOW_GENERIC_PARAMETER(FlowGenericParameterTree.class),
    FLOW_GENERIC_PARAMETER_CLAUSE(FlowGenericParameterClauseTree.class),
    FLOW_PARAMETERIZED_GENERICS_TYPE(FlowParameterizedGenericsTypeTree.class),
    FLOW_IMPLEMENTS_CLAUSE(FlowImplementsClauseTree.class),
    FLOW_OBJECT_TYPE(FlowObjectTypeTree.class),
    FLOW_PROPERTY_DEFINITION(FlowPropertyDefinitionTree.class),
    FLOW_SIMPLE_PROPERTY_DEFINITION_KEY(FlowSimplePropertyDefinitionKeyTree.class),
    FLOW_METHOD_PROPERTY_DEFINITION_KEY(FlowMethodPropertyDefinitionKeyTree.class),
    FLOW_INDEXER_PROPERTY_DEFINITION_KEY(FlowIndexerPropertyDefinitionKeyTree.class),
    FLOW_TYPE_ANNOTATION(FlowTypeAnnotationTree.class),
    FLOW_PARENTHESISED_TYPE(FlowParenthesisedTypeTree.class),
    FLOW_TUPLE_TYPE(FlowTupleTypeTree.class),
    FLOW_NAMESPACED_TYPE(FlowNamespacedTypeTree.class),
    FLOW_TYPEOF_TYPE(FlowTypeofTypeTree.class),
    FLOW_CASTING_EXPRESSION(FlowCastingExpressionTree.class),
    FLOW_ARRAY_TYPE_WITH_KEYWORD(FlowArrayTypeTree.class),
    FLOW_ARRAY_TYPE_SHORTHAND(FlowArrayTypeShorthandTree.class),
    FLOW_TYPED_BINDING_ELEMENT(FlowTypedBindingElementTree.class),
    FLOW_OPTIONAL_BINDING_ELEMENT(FlowOptionalBindingElementTree.class),
    FLOW_TYPE_ALIAS_STATEMENT(FlowTypeAliasStatementTree.class),
    FLOW_INTERFACE_DECLARATION(FlowInterfaceDeclarationTree.class),
    FLOW_DECLARE(FlowDeclareTree.class),
    FLOW_MODULE(FlowModuleTree.class),
    FLOW_MODULE_EXPORTS(FlowModuleExportsTree.class),
    FLOW_FUNCTION_SIGNATURE(FlowFunctionSignatureTree.class),
    FLOW_OPAQUE_TYPE(FlowOpaqueTypeTree.class),

    TOKEN(SyntaxToken.class),

    TRIVIA(SyntaxTrivia.class);

    final Class<? extends Tree> associatedInterface;

    Kind(Class<? extends Tree> associatedInterface) {
      this.associatedInterface = associatedInterface;
    }

    public Class<? extends Tree> getAssociatedInterface() {
      return associatedInterface;
    }

    @Override
    public boolean contains(Kinds other) {
      return this.equals(other);
    }

  }

}
