import "reflect-metadata";

function ClassDecoratorParams(param1: number, param2: string) {
    return function(
        target: Function // The class the decorator is declared on
    ) {
        //console.log("ClassDecoratorParams(" + param1 + ", '" + param2 + "') called on: ", target);
        console.log("ClassDecoratorParams(" + param1 + ", '" + param2 + "'). ");
    }
}

function f(s : string) {
    console.log("f(): evaluated " + s);
    return function (target, propertyKey: string, descriptor: PropertyDescriptor) : void{
        console.log("f(): called");
    }
}



function enumerable(isEnumerable: boolean) {
    return (target: Object, propertyKey: string, descriptor: TypedPropertyDescriptor<any>) => {
        descriptor.enumerable = isEnumerable;
        return descriptor;
    };
}
function g() {
    console.log("g(): evaluated " );
    return function (target, propertyKey: string, descriptor: PropertyDescriptor) : any{
        let originalMethod = descriptor.value;

        // NOTE: Do not use arrow syntax here. Use a function expression in
        // order to use the correct value of `this` in this method (see notes below)
        descriptor.value = function(...args: any[]) {
            console.log("The method args are: " + JSON.stringify(args)); // pre
            let result = originalMethod.apply(this, args);               // run and store the result
            console.log("The return value is: " + result);               // post
            return result;                                               // return the result of the original method
        };
    }
}



interface Person {
    firstName: string;
    lastName: string;
}

@ClassDecoratorParams(1, 'class student')
class Student {

    fullName: string;

    constructor(public firstName, public lastName, public middleInitial?) {
        this.fullName = firstName + " " + middleInitial + " " + lastName;
    }

    @f('a')
    @enumerable(true)
    greet() {
        return "Hi student " + this.fullName;
    }

    @g()
    greetP(person: Person) {
        return "Hello, " + person.firstName + " " + person.lastName;
    }
}


function greeter(person: Person) {
    return "Hello, " + person.firstName + " " + person.lastName;
}


var user = new Student(" Marina", 'Elef');

user.greet();
user.greetP(user);
//document.body.innerHTML = user.greet();