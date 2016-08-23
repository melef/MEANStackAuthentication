"use strict";
var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
require("reflect-metadata");
function ClassDecoratorParams(param1, param2) {
    return function (target // The class the decorator is declared on
        ) {
        //console.log("ClassDecoratorParams(" + param1 + ", '" + param2 + "') called on: ", target);
        console.log("ClassDecoratorParams(" + param1 + ", '" + param2 + "'). ");
    };
}
function f(s) {
    console.log("f(): evaluated " + s);
    return function (target, propertyKey, descriptor) {
        console.log("f(): called");
    };
}
function enumerable(isEnumerable) {
    return (target, propertyKey, descriptor) => {
        descriptor.enumerable = isEnumerable;
        return descriptor;
    };
}
function g() {
    console.log("g(): evaluated ");
    return function (target, propertyKey, descriptor) {
        let originalMethod = descriptor.value;
        // NOTE: Do not use arrow syntax here. Use a function expression in
        // order to use the correct value of `this` in this method (see notes below)
        descriptor.value = function (...args) {
            console.log("The method args are: " + JSON.stringify(args)); // pre
            let result = originalMethod.apply(this, args); // run and store the result
            console.log("The return value is: " + result); // post
            return result; // return the result of the original method
        };
    };
}
let Student = class Student {
    constructor(firstName, lastName, middleInitial) {
        this.firstName = firstName;
        this.lastName = lastName;
        this.middleInitial = middleInitial;
        this.fullName = firstName + " " + middleInitial + " " + lastName;
    }
    greet() {
        return "Hi student " + this.fullName;
    }
    greetP(person) {
        return "Hello, " + person.firstName + " " + person.lastName;
    }
};
__decorate([
    f('a'),
    enumerable(true)
], Student.prototype, "greet", null);
__decorate([
    g()
], Student.prototype, "greetP", null);
Student = __decorate([
    ClassDecoratorParams(1, 'class student')
], Student);
function greeter(person) {
    return "Hello, " + person.firstName + " " + person.lastName;
}
var user = new Student(" Marina", 'Elef');
user.greet();
user.greetP(user);
//document.body.innerHTML = user.greet(); 
//# sourceMappingURL=greeter.js.map