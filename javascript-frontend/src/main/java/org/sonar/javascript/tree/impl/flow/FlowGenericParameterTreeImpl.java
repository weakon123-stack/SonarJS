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
package org.sonar.javascript.tree.impl.flow;

import com.google.common.collect.Iterators;
import java.util.Iterator;
import javax.annotation.Nullable;
import org.sonar.javascript.tree.impl.JavaScriptTree;
import org.sonar.plugins.javascript.api.tree.Tree;
import org.sonar.plugins.javascript.api.tree.expression.IdentifierTree;
import org.sonar.plugins.javascript.api.tree.flow.FlowGenericParameterTree;
import org.sonar.plugins.javascript.api.tree.flow.FlowTypeAnnotationTree;
import org.sonar.plugins.javascript.api.tree.flow.FlowTypeTree;
import org.sonar.plugins.javascript.api.tree.lexical.SyntaxToken;
import org.sonar.plugins.javascript.api.visitors.DoubleDispatchVisitor;

public class FlowGenericParameterTreeImpl extends JavaScriptTree implements FlowGenericParameterTree {

  private final IdentifierTree identifier;
  private final FlowTypeAnnotationTree superTypeAnnotation;
  private final SyntaxToken equalToken;
  private final FlowTypeTree defaultType;

  public FlowGenericParameterTreeImpl(
    IdentifierTree identifier,
    @Nullable FlowTypeAnnotationTree superTypeAnnotation,
    @Nullable SyntaxToken equalToken, @Nullable FlowTypeTree defaultType
  ) {
    this.identifier = identifier;
    this.superTypeAnnotation = superTypeAnnotation;
    this.equalToken = equalToken;
    this.defaultType = defaultType;
  }

  @Override
  public Kind getKind() {
    return Kind.FLOW_GENERIC_PARAMETER;
  }

  @Override
  public Iterator<Tree> childrenIterator() {
    return Iterators.forArray(identifier, superTypeAnnotation, equalToken, defaultType);
  }

  @Override
  public IdentifierTree identifier() {
    return identifier;
  }

  @Nullable
  @Override
  public FlowTypeAnnotationTree superTypeAnnotation() {
    return superTypeAnnotation;
  }

  @Nullable
  @Override
  public SyntaxToken equalToken() {
    return equalToken;
  }

  @Nullable
  @Override
  public FlowTypeTree defaultType() {
    return defaultType;
  }

  @Override
  public void accept(DoubleDispatchVisitor visitor) {
    visitor.visitFlowGenericParameter(this);
  }
}
