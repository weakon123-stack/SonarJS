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
import { rule } from "../../src/rules/no-accessor-field-mismatch";
import { RuleTester } from "eslint";

const tsParserPath = require.resolve("@typescript-eslint/parser");
const ruleTester = new RuleTester({
  parserOptions: { ecmaVersion: 2018, sourceType: "module" },
  parser: tsParserPath,
});

function invalid(code: string) {
  const errors: RuleTester.TestCaseError[] = [];
  const lines = code.split("\n");
  for (let i = 1; i <= lines.length; i++) {
    const line = lines[i - 1];
    if (line.includes("// Noncompliant")) {
      errors.push({
        line: i,
        endLine: i,
      });
    }
  }
  return {
    code: code,
    errors,
  };
}

ruleTester.run("Getters and setters should access the expected fields", rule, {
  valid: [
    {
      code: `
        class OK {
          private x: string;
          private _y = "hello";
        
          constructor(private z: number) {
            
          }
        
          public getX(): string {
            return this.x;
          }
        
          public get y(): string {
            return this._y;
          }
        
          public set y(y: string) {
            this._y = y;
          }
        
          public getY(): string {
            return this._y;
          }
        
          public getZ() {
            return this.z;
          }
        
          public setX(x: string) {
            this.x = x;
          }
        }`,
    },
    {
      code: `
        class Exceptions1 {
          private x: string;
          private y = "hello";
        
          constructor(private z: number, private _v: number, private [a, b], w: number) {
            
          }
        
          public getW(): string { // Compliant, w does not exist
            return this.x;
          }
        
          private GetY(): number { // Compliant, private method
            return this.z;
          }
        
          public setW(w: string) { // Compliant, w does not exist as a field, only a parameter of the constructor
            this.x = w;
          }
        
          public getY(someParam: number) { // Compliant, not a zero-parameters getter
            return 3;
          }
        
          public setZ(y: string, someParam: number) { // Compliant, not a one-parameters setter
            this.z = 3;
          }
        
          public setY(x: string) // Compliant, overload
          public setY(y: string) {
            this.y = y;
          }
        
          public getZ() { // Compliant, does not match "return this.?;" pattern
            this.setZ("",1);
          }
          
          public abstract GetZ(): string; // Compliant, abstract method with no body
          
          public set v(z:number) { // Compliant, does not match "this.? =" pattern
            this.x;
          }
        
          public get v() { // Compliant, not a single return statement
            if (this.z) {
              return 1;
            } else {
              return this.z;
            }
          }
        
          public getV() { // Compliant
            return \`v is ${this.z}\`;
          }
        }`,
    },
    {
      code: `
        class Exceptions2 {
          private x: string;
          private y = "hello";
        
          public GetY(): number { // Compliant, multiple statements
            const val = doSomething();
            return this.z;
          }
          
          public getY(someParam: number) { // Compliant, not a zero-parameters getter
            return 3;
          }
          
          public get ["i" + "2"]() { // FN - we do not handle computed properties
            return this.x;
          }
        }`,
    },
    {
      code: `
        export const ObjectLiteral = {
          w_: "blah",
          _x: "blah",
          _experiments: "blah",
          'z': 3,

          getExperiments(): string {
            return this._experiments;
          },
          
          get X() {
            return this._x;
          },
          
          set x(newX) {
            this._x = newX;
          },
          
          get z() {
            return this.z;
          },
          
          setZ(x: number) {
            this.z = x;
          },
          
          set w(x: number) {
            this.w_ = x;
          },
          
          get myVal() {
            return this.myVal_;
          },
          
          set myVal(v) {
            this.myVal_ = v;
          },
          
          ...theRest
        };`,
    },
  ],
  invalid: [
    {
      code: `
      class NOK_CheckLocation {
        private x: string;
        private _y = "hello";
      
        public setY(y: number) {}   // Noncompliant
      
        public get X(): string {   // Noncompliant
            return this._y;
        }
      }`,
      errors: [
        {
          message: `{"message":"Refactor this setter so that it actually refers to the property '_y'.","secondaryLocations":[{"message":"Property which should be referred.","column":8,"line":4,"endColumn":29,"endLine":4}]}`,
          line: 6,
          column: 16,
          endLine: 6,
          endColumn: 20,
        },
        {
          message: `{"message":"Refactor this getter so that it actually refers to the property 'x'.","secondaryLocations":[{"message":"Property which should be referred.","column":8,"line":3,"endColumn":26,"endLine":3}]}`,
          line: 8,
          column: 20,
          endLine: 8,
          endColumn: 21,
        },
      ],
    },
    {
      code: `
      class NOK {
        static _filter: string = '';
        private _filter: string = '';
      
        private _x: number = 2;
        static _x: number = 1;
      
        private _y: number = 2; // Secondary
        static _y: number = 1;
      
        public get filter(): string {
          return this._filter; // OK
        }
      
        public get x(): number {
          return Issue476._x;
        }
      
        public get y(): number { return this._x; }  // Noncompliant
      }`,
      errors: [
        {
          message: `{"message":"Refactor this getter so that it actually refers to the property '_y'.","secondaryLocations":[{"message":"Property which should be referred.","column":8,"line":9,"endColumn":31,"endLine":9}]}`,
          line: 20,
          column: 20,
          endLine: 20,
          endColumn: 21,
        },
      ],
    },
    invalid(`
    class NOK {
      private x: string;
      private _y = "hello";
      private z = 0;
    
      constructor(private w: number, readonly ro: number) {
        
      }
    
      public setX(x: number) {} // Noncompliant
    
      public GetX(): string { // Noncompliant
        return this._y;
      }
    
      public get y(): number { // Noncompliant
        return this.z;
      }
    
      public set y(y: number) {} // Noncompliant
    
      public getY(): number { // Noncompliant
        return this.z;
      }
    
      public SetZ(z: string) { // Noncompliant
        this.x = z;
      }
    
      public setW(x: string) { // Noncompliant
        this.x = x;
      }
    
      public setRO(ro: number) { // Noncompliant
        this.z = ro;
      }
    }`),
    invalid(`
    const nokObj = {
      w_: 0,
      x : 3,
      _y : 1,
      'z': 2,
      ["a" + 1]: 1,
    
      get w() { // Noncompliant
        return this.x;
      },
    
      get y() { // Noncompliant
        return this.w_;
      },
    
      setX(x: number) { // Noncompliant
        this._y = x;
      },
      
      get z() { // Noncompliant
        return this.x;
      },
      
      setZ(x: number) { // Noncompliant
        this.y = x;
      },
      
      get a1() { // FN - cannot determine computed field a1 existence
        return this.x;
      },
    }`),
  ],
});
