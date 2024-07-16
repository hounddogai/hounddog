// Define a class representing a Person
class Person {
    // Properties
    private fullName: string;
    private phoneNumber: string;
    private ssn: string;

    // Constructor
    constructor(fullName: string, phoneNumber: string, ssn: string) {
        this.fullName = fullName;
        this.phoneNumber = phoneNumber;
        this.ssn = ssn;
    }

    // Method to display person's information
    displayInfo(): void {
        console.log(ssn);
        console.log(`Name: ${this.fullName}`);
        console.log(`Phone Number: ${this.phoneNumber}`);
        console.log(`SSN: ${this.ssn}`);
    }
}

// Create an instance of the Person class
let person1 = new Person('John Doe', '123-456-7890', '123-45-6789');

// Display person's information
person1.displayInfo();