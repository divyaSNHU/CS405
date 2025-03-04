Green Pace Developer: Security Policy Guide Template

 
Green Pace Secure Development Policy 
Contents
Overview	2
Purpose	2
Scope	2
Module Three Milestone	2
Ten Core Security Principles	2
C/C++ Ten Coding Standards	3
Coding Standard 1	4
Coding Standard 2	5
Coding Standard 3	6
Coding Standard 4	7
Coding Standard 5	8
Coding Standard 6	9
Coding Standard 7	10
Coding Standard 8	11
Coding Standard 9	13
Coding Standard 10	14
Defense-in-Depth Illustration	15
Project One	15
1.	Revise the C/C++ Standards	15
2.	Risk Assessment	15
3.	Automated Detection	15
4.	Automation	15
5.	Summary of Risk Assessments	16
6.	Create Policies for Encryption and Triple A	16
7.	Map the Principles	17
Audit Controls and Management	18
Enforcement	18
Exceptions Process	18
Distribution	19
Policy Change Control	19
Policy Version History	19
Appendix A Lookups	19
Approved C/C++ Language Acronyms	19

 
Overview
Software development at Green Pace requires consistent implementation of secure principles to all developed applications. Consistent approaches and methodologies must be maintained through all policies that are uniformly defined, implemented, governed, and maintained over time.

Purpose
This policy defines the core security principles; C/C++ coding standards; authorization, authentication, and auditing standards; and data encryption standards. This article explains the differences between policy, standards, principles, and practices (guidelines and procedure): Understanding the Hierarchy of Principles, Policies, Standards, Procedures, and Guidelines.

Scope
This document applies to all staff that create, deploy, or support custom software at Green Pace.

Module Three Milestone 
Ten Core Security Principles
Principles	Write a short paragraph explaining each of the 10 principles of security.
1.	Validate Input Data	This security principle validates the inputs of the data that will be inserted. It ensures the inputs are correctly formatted and in correct ranges as expected. It helps in detecting the overflows of the data, which could protect from vulnerabilities.
2.	Heed Compiler Warnings	We must pay attention towards Compiler warnings as they will show any potential error in the code or if any practices that are not safe and may cause security issues.
3.	Architect and Design for Security Policies	During the designing of the software development, need to consider the security as well in the designing like ensuring all the authentications and permissions, designing of firewalls to avoid security issues during usage of the application.
4.	Keep It Simple	We need to make the code as simple as possible to avoid possibly vulnerabilities as others will get hard to understand and detect the issue. Keeping it simple will make it easy to understand, and to maintain it.
5.	Default Deny	Whenever we are setting up the user permissions and authentications, default deny the users and only allow the authorized user to access. which will ensure that unauthorized users can’t access the system.
6.	Adhere to the Principle of Least Privilege	When providing permissions to the user give only minimum permissions that enough of them to work to avoid the damage.
7.	Sanitize Data Sent to Other Systems	Whenever sending data to other systems we need to make sure that it is properly validated and sanitized by making sure it doesn’t contain any sensitive data that could cause security issue.
8.	Practice Defense in Depth 	We need to have multiple layers of data protection like having multiple layers of firewalls to avoid security vulnerabilities as if one layer compromised still there will be others to protect the data.
9.	Use Effective Quality Assurance Techniques	Having a greater number of quality testing and checks will ensure detecting the bugs in the code that may cause vulnerabilities before the code is deployed.
10.	Adopt a Secure Coding Standard	We need to adopt a secure coding standard that guides in ensuring the consistency in the code that we develop and helps in minimizing the security vulnerabilities.

C/C++ Ten Coding Standards
Complete the coding standards portion of the template according to the Module Three milestone requirements. In Project One, follow the instructions to add a layer of security to the existing coding standards. Please start each standard on a new page, as they may take up more than one page. The first seven coding standards are labeled by category. The last three are blank so you may choose three additional standards. Be sure to label them by category and give them a sequential number for that category. Add compliant and noncompliant sections as needed to each coding standard. 
Coding Standard 1

Coding Standard	Label	Name of Standard
Data Type	[STD-001-CPP]	Using appropriate data types for deriving the variables will helps in minimizing the data overflow and helps with memory efficiency. 

Noncompliant Code
In below code for all the variables we used only one type of data type, instead of defining them appropriate type. This will cause memory efficiency issue and causes data overflow issues.
#include <iostream>

int main() {
    int age = 30;          // age will be always positive integer
    int price = 2.89;      // price here is decimal
    int flag = 1;          // flag should be Boolean
    
    std::cout << "Age: " << age << std::endl;
    std::cout << "Price: " << price << std::endl;
    std::cout << "flag: " << flag << std::endl;

    return 0;
}

Compliant Code
Below code defined each variable with appropriate data type, this will ensure memory efficiency and resolves data overflow issues.
#include <iostream>

int main() {
    unsigned int age = 30;    // age will be always positive integer
    float price = 2.89;       // price here is decimal
    bool flag = true;         // flag should be Boolean
    
    std::cout << "Age: " << age << std::endl;
    std::cout << "Price: " << price << std::endl;
    std::cout << "flag: " << flag << std::endl;

    return 0;
}

Note: Stop here for the milestone. Complete this section for Project One in Module Six.
Principles(s): 
3. Architect and Design for Security Policies
4. Keep it simple

Threat Level
Severity	Likelihood	Remediation Cost	Priority	Level
High	Unlikely	High	P3	L3

Automation
Tool	Version	Checker	Description Tool
LDRA tool suite	9.7.1
 	286 S, 287 S	Fully implemented
Parasoft C/C++test	2024.2	CERT_CPP-DCL60-a	The One Definition Rule shall not be violated
Polyspace Bug Finder	R2024a	CERT C++: DCL60-CPP	Checks for inline constraints not respected (rule partially covered)
CodeSonar	8.3p0	LANG.STRUCT.DEF.FDH
LANG.STRUCT.DEF.ODH	Function defined in header file
Object defined in header file
 
Coding Standard 2

Coding Standard	Label	Name of Standard
Data Value	[STD-002-CPP]	Standard data values should be used to ensure consistency through the code and helps in easy understanding and maintaining it.

Noncompliant Code
In below code, directly the area is calculated by assigning the values instead of deriving them separately. This causes confusion to understand and also, we cannot use those values throughout the code since the value is hard coded.
#include <iostream>

int main() {
    double area = 15.2 * 11.5;   //length and width value are hardcoded 
    
    std::cout << "Area of a Rectangle: " << area << std::endl;

    return 0;
}

Compliant Code
Instead deriving each variable separately and applying the formula will make the code more easily to understand and also, we can re-use these variables later in the code and will be easy to modify.
#include <iostream>

int main() {
    double lenth = 15.2;    // defined length
    double width = 11.5;    // defined width
    double area = length * width

    std::cout << "Area of a Rectangle: " << area << std::endl;

    return 0;
}

Note: Stop here for the milestone. Complete this section for Project One in Module Six.
Principles(s): 
1.Validate Input
4.Keep it simple

Threat Level
Severity	Likelihood	Remediation Cost	Priority	Level
High	Probable	Medium	P12	L1

Automation
Tool	Version	Checker	Description Tool
LDRA tool suite	9.7.1
 	53 D, 69 D, 631 S, 652 S	Partially implemented
Parasoft C/C++test	2024.2	CERT_CPP-EXP53-a	Avoid use before initialization
Astrée	22.10	uninitialized-read	Partially checked
Clang
3.9	-Wuninitialized
clang-analyzer-core.UndefinedBinaryOperatorResult	Does not catch all instances of this rule, such as uninitialized values read from heap-allocated memory
 
Coding Standard 3

Coding Standard	Label	Name of Standard
String Correctness	[STD-003-CPP]	This standard does not attempt to create a string from a null pointer

Noncompliant Code
In the below code, a string object is created from the result of a call std::gentenv(), but if it returns null pointer when failed then it leads to some undefined behavior and get issues.
#include <cstdlib>
#include <string>
  
void f() {
  std::string tmp(std::getenv("TMP"));
  if (!tmp.empty()) {
    // ...
  }
}


Compliant Code
In the below code it checks for null before creating the std::string.
#include <cstdlib>
#include <string>
  
void f() {
  const char *tmpPtrVal = std::getenv("TMP");
  std::string tmp(tmpPtrVal ? tmpPtrVal : "");
  if (!tmp.empty()) {
    // ...
  }
}


Note: Stop here for the milestone. Complete this section for Project One in Module Six.
Principles(s): 
2. Heed compiler warning

Threat Level
Severity	Likelihood	Remediation Cost	Priority	Level
High	Likely	Medium	P1	L1

Automation
Tool	Version	Checker	Description Tool
Astree	22.10	assert_failure	-
CodeSonar	8.3p0	LANG.MEM.NPD	Null Pointer Dereference
Parasoft C/C++test	2024.2	CERT_CPP-STR51-a	Avoid null pointer dereferencing
Polyspace Bug Finder	R2024a	CERT C++: STR51-CPP	Checks for string operations on null pointer (rule partially covered).
 
Coding Standard 4

Coding Standard	Label	Name of Standard
SQL Injection	[STD-004-CPP]	This standard prevents SQL Injection

Noncompliant Code
The JDBC library provides an API for building SQL commands that sanitize untrusted data. The java.sql.PreparedStatement class properly escapes input strings, preventing SQL injection when used correctly. This code example modifies the doPrivilegedAction() method to use a PreparedStatement instead of java.sql.Statement. However, the prepared statement still permits a SQL injection attack by incorporating the unsanitized input argument username into the prepared statement.
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
 
class Login {
  public Connection getConnection() throws SQLException {
    DriverManager.registerDriver(new
            com.microsoft.sqlserver.jdbc.SQLServerDriver());
    String dbConnection =
      PropertyManager.getProperty("db.connection");
    // Can hold some value like
    // "jdbc:microsoft:sqlserver://<HOST>:1433,<UID>,<PWD>"
    return DriverManager.getConnection(dbConnection);
  }
 
  String hashPassword(char[] password) {
    // Create hash of password
  }
 
  public void doPrivilegedAction(
    String username, char[] password
  ) throws SQLException {
    Connection connection = getConnection();
    if (connection == null) {
      // Handle error
    }
    try {
      String pwd = hashPassword(password);
      String sqlString = "select * from db_user where username=" +
        username + " and password =" + pwd;     
      PreparedStatement stmt = connection.prepareStatement(sqlString);
 
      ResultSet rs = stmt.executeQuery();
      if (!rs.next()) {
        throw new SecurityException("User name or password incorrect");
      }
 
      // Authenticated; proceed
    } finally {
      try {
        connection.close();
      } catch (SQLException x) {
        // Forward to handler
      }
    }
  }
}


Compliant Code
Below code uses a parametric query with a? character as a placeholder for the argument. This code also validates the length of the username argument, preventing an attacker from submitting an arbitrarily long username.
public void doPrivilegedAction(
  String username, char[] password
) throws SQLException {
  Connection connection = getConnection();
  if (connection == null) {
    // Handle error
  }
  try {
    String pwd = hashPassword(password);
 
    // Validate username length
    if (username.length() > 8) {
      // Handle error
    }
 
    String sqlString =
      "select * from db_user where username=? and password=?";
    PreparedStatement stmt = connection.prepareStatement(sqlString);
    stmt.setString(1, username);
    stmt.setString(2, pwd);
    ResultSet rs = stmt.executeQuery();
    if (!rs.next()) {
      throw new SecurityException("User name or password incorrect");
    }
 
    // Authenticated; proceed
  } finally {
    try {
      connection.close();
    } catch (SQLException x) {
      // Forward to handler
    }
  }
}


Note: Stop here for the milestone. Complete this section for Project One in Module Six.
Principles(s): 
1. Validate input data
7. Sanitize Data Sent to Other Systems

Threat Level
Severity	Likelihood	Remediation Cost	Priority	Level
High	Likely	Medium	P18	L1

Automation
Tool	Version	Checker	Description Tool
The Checker Framework	2.1.3	Tainting Checker	Trust and security errors (see Chapter 8)
CodeSonar	8.1p0	JAVA.IO.INJ.SQL	SQL injection
Coverity	7.5	SQLI
FB.SQL_PREPARED_STATEMENT_GENERATED_
FB.SQL_NONCONSTANT_STRING_PASSED_TO_EXECUTE	Implemented
Findbugs	1.0	SQL_NONCONSTANT_STRING_PASSED_TO_EXECUTE	Implemented
 
Coding Standard 5

Coding Standard	Label	Name of Standard
Memory Protection	[STD-005-LLL]	This standard does not access freed memory

Noncompliant Code
In the below code s is dereferenced after it has been deallocated. If this access results in a write-after-free, the vulnerability can be exploited to run arbitrary code with the permissions of the vulnerable process. Typically, dynamic memory allocations and deallocations are far removed, making it difficult to recognize and diagnose such problems.
#include <new>
  
struct S {
  void f();
};
  
void g() noexcept(false) {
  S *s = new S;
  // ...
  delete s;
  // ...
  s->f();
}


Compliant Code
In the below code, the dynamically allocated memory is not deallocated until it is no longer required.
#include <new>
 
struct S {
  void f();
};
 
void g() noexcept(false) {
  S *s = new S;
  // ...
  s->f();
  delete s;
}

Note: Stop here for the milestone. Complete this section for Project One in Module Six.
Principles(s): 
Heed compiler warnings
Default Deny

Threat Level
Severity	Likelihood	Remediation Cost	Priority	Level
High	Likely	Medium	P18	L1

Automation
Tool	Version	Checker	Description Tool
Clang	3.9	clang-analyzer-cplusplus.NewDelete
clang-analyzer-alpha.security.ArrayBoundV2 	Checked by clang-tidy, but does not catch all violations of this rule.
CodeSonar	8.3p0	ALLOC.UAF	Use after free
LDRA tool suite	9.7.1
 	483 S, 484 S	Partially implemented
Coverity	v7.5.0	USE_AFTER_FREE	Can detect the specific instances where memory is deallocated more than once or read/written to the target of a freed pointer
 
Coding Standard 6

Coding Standard	Label	Name of Standard
Assertions	[STD-006-CPP]	This standard is to use a static assertion to test the value of a constant expression


Noncompliant Code
In the below code, we use the assert () macro to assert a property concerning a memory-mapped structure that is essential for the code to behave correctly
#include <assert.h>
  
struct timer {
  unsigned char MODE;
  unsigned int DATA;
  unsigned int COUNT;
};
  
int func(void) {
  assert(sizeof(struct timer) == sizeof(unsigned char) + sizeof(unsigned int) + sizeof(unsigned int));
}


Compliant Code
In below code for assertions involving only constant expressions, a preprocessor conditional statement is used
struct timer {
  unsigned char MODE;
  unsigned int DATA;
  unsigned int COUNT;
};
 
#if (sizeof(struct timer) != (sizeof(unsigned char) + sizeof(unsigned int) + sizeof(unsigned int)))
  #error "Structure must not have any padding"
#endif


Note: Stop here for the milestone. Complete this section for Project One in Module Six.
Principles(s): 
Heed compiler warnings
Adopt a Secure Coding Standard

Threat Level
Severity	Likelihood	Remediation Cost	Priority	Level
Low	Unlikely	High	P1	L3

Automation
Tool	Version	Checker	Description Tool
Clang	3.9	misc-static-assert	Checked by clang-tidy
CodeSonar	8.3p0	(customization)	Users can implement a custom check that reports uses of the assert() macro
Compass/ROSE			Could detect violations of this rule merely by looking for calls to assert(), and if it can evaluate the assertion (due to all values being known at compile time), then the code should use static-assert instead; this assumes ROSE can recognize macro invocation
ECLAIR	1.2	CC2.DCL03	Fully implemented
 
Coding Standard 7

Coding Standard	Label	Name of Standard
Exceptions	[STD-007-CPP]	This standard does not abruptly terminate the program


Noncompliant Code
In the Below code, the call to f(), which was registered as an exit handler with std::at_exit(), may result in a call to std::terminate() because throwing_func() may throw an exception
#include <cstdlib>
  
void throwing_func() noexcept(false);
  
void f() { // Not invoked by the program except as an exit handler.
  throwing_func();
}
  
int main() {
  if (0 != std::atexit(f)) {
    // Handle error
  }
  // ...
}


Compliant Code
In the Below code, f() handles all exceptions thrown by throwing_func() and does not rethrow
#include <cstdlib>
 
void throwing_func() noexcept(false);
 
void f() { // Not invoked by the program except as an exit handler.
  try {
    throwing_func();
  } catch (...) {
    // Handle error
  }
}
 
int main() {
  if (0 != std::atexit(f)) {
    // Handle error
  }
  // ...
}


Note: Stop here for the milestone. Complete this section for Project One in Module Six.
Principles(s): 
Use Effective Quality Assurance Techniques

Threat Level
Severity	Likelihood	Remediation Cost	Priority	Level
Low	Probable	Medium	P4	L3

Automation
Tool	Version	Checker	Description Tool
Astrée	22.10	stdlib-use	Partially checked
CodeSonar	8.3p0	BADFUNC.ABORT
BADFUNC.EXIT	Use of abort
Use of exit
Polyspace Bug Finder	R2024a	CERT C++: ERR50-CPP	Checks for implicit call to terminate () function (rule partially covered)
LDRA tool suite	9.7.1
 	122 S	Enhanced Enforcement
 
Coding Standard 8

Coding Standard	Label	Name of Standard
Expressions	[STD-008-CPP]	This standard do not depend on the order of evaluation for side effects


Noncompliant Code
In the below code, i is evaluated more than once in an sequenced manner, so the behavior of the expression is undefined.
void f(int i, const int *b) {
  int a = i + b[++i];
  // ...
}


Compliant Code
In the below code, independent of the order of evaluation of the operands and can each be interpreted in only one way
void f(int i, const int *b) {
  ++i;
  int a = i + b[i];
  // ...
}


Note: Stop here for the milestone. Complete this section for Project One in Module Six.
Principles(s): 
Keep it simple

Threat Level
Severity	Likelihood	Remediation Cost	Priority	Level
Medium	Probable	Medium	P8	L2

Automation
Tool	Version	Checker	Description Tool
Axivion Bauhaus Suite	7.2.0	CertC++-EXP50	
Clang	3.9	-Wunsequenced	Can detect simple violations of this rule where path-sensitive analysis is not required
CodeSonar	8.3p0	LANG.STRUCT.SE.DEC
LANG.STRUCT.SE.INC	Side Effects in Expression with Decrement
Side Effects in Expression with Increment
Compass/ROSE			Can detect simple violations of this rule. It needs to examine each expression and make sure that no variable is modified twice in the expression. It also must check that no variable is modified once, then read elsewhere, with the single exception that a variable may appear on both the left and right of an assignment operator
 
Coding Standard 9 

Coding Standard	Label	Name of Standard
Object Oriented Programming	[STD-009-CPP]	 Do not invoke virtual functions from constructors or destructors


Noncompliant Code
In the below code, the base class attempts to seize and release an object's resources through calls to virtual functions from the constructor and destructor. However, the B::B() constructor calls B::seize() rather than D::seize(). Likewise, the B::~B() destructor calls B::release() rather than D::release().
struct B {
  B() { seize(); }
  virtual ~B() { release(); }
  
protected:
  virtual void seize();
  virtual void release();
};
 
struct D : B {
  virtual ~D() = default;
  
protected:
  void seize() override {
    B::seize();
    // Get derived resources...
  }
  
  void release() override {
    // Release derived resources...
    B::release();
  }
};


Compliant Code
In the below code, the constructors and destructors call a nonvirtual, private member function (suffixed with mine) instead of calling a virtual function. The result is that each class is responsible for seizing and releasing its own resources.
class B {
  void seize_mine();
  void release_mine();
   
public:
  B() { seize_mine(); }
  virtual ~B() { release_mine(); }
 
protected:
  virtual void seize() { seize_mine(); }
  virtual void release() { release_mine(); }
};
 
class D : public B {
  void seize_mine();
  void release_mine();
   
public:
  D() { seize_mine(); }
  virtual ~D() { release_mine(); }
 
protected:
  void seize() override {
    B::seize();
    seize_mine();
  }
   
  void release() override {
    release_mine();
    B::release();
  }
};


Note: Stop here for the milestone. Complete this section for Project One in Module Six.
Principles(s): 
Keep it simple
Adopt a secure coding standard

Threat Level
Severity	Likelihood	Remediation Cost	Priority	Level
Low	Unlikely	Medium	P2	L3

Automation
Tool	Version	Checker	Description Tool
Astrée	22.10	virtual-call-in-constructor
invalid_function_pointer	Fully checked
Axivion Bauhaus Suite	7.2.0	CertC++-OOP50	
Clang	3.9	clang-analyzer-alpha.cplusplus.VirtualCall	Checked by clang-tidy
CodeSonar	8.3p0	LANG.STRUCT.VCALL_IN_CTOR
LANG.STRUCT.VCALL_IN_DTOR	Virtual Call in Constructor
Virtual Call in Destructor
 
Coding Standard 10

Coding Standard	Label	Name of Standard
Containers	[STD-010-CPP]	Use valid references, pointers, and iterators to reference elements of a container


Noncompliant Code
In the below code, pos is invalidated after the first call to insert(), and subsequent loop iterations have undefined behavior.
#include <deque>
  
void f(const double *items, std::size_t count) {
  std::deque<double> d;
  auto pos = d.begin();
  for (std::size_t i = 0; i < count; ++i, ++pos) {
    d.insert(pos, items[i] + 41.0);
  }
}


Compliant Code
In the below code, pos is assigned a valid iterator on each insertion, preventing undefined behavior.
#include <deque>
  
void f(const double *items, std::size_t count) {
  std::deque<double> d;
  auto pos = d.begin();
  for (std::size_t i = 0; i < count; ++i, ++pos) {
    pos = d.insert(pos, items[i] + 41.0);
  }
}


Note: Stop here for the milestone. Complete this section for Project One in Module Six.
Principles(s): 
Heed compiler warnings

Threat Level
Severity	Likelihood	Remediation Cost	Priority	Level
High	Probable	High	P6	L2

Automation
Tool	Version	Checker	Description Tool
Helix QAC	2024.4	DF4746, DF4747, DF4748, DF4749	
Klocwork	2024.4	ITER.CONTAINER.MODIFIED	
Parasoft C/C++test	2024.2	CERT_CPP-CTR51-a	Do not modify container while iterating over it
Polyspace Bug Finder	R2024a	CERT C++: CTR51-CPP
Checks for use of invalid iterator (rule partially covered).
 
Defense-in-Depth Illustration
This illustration provides a visual representation of the defense-in-depth best practice of layered security.

 

Project One
There are seven steps outlined below that align with the elements you will be graded on in the accompanying rubric. When you complete these steps, you will have finished the security policy.

Revise the C/C++ Standards
You completed one of these tables for each of your standards in the Module Three milestone. In Project One, add revisions to improve the explanation and examples as needed. Add rows to accommodate additional examples of compliant and noncompliant code. Coding standards begin on the security policy.

Risk Assessment 
Complete this section on the coding standards tables. Enter high, medium, or low for each of the headers, then rate it overall using a scale from 1 to 5, 5 being the greatest threat. You will address each of the seven policy standards. Fill in the columns of severity, likelihood, remediation cost, priority, and level using the values provided in the appendix.

Automated Detection
Complete this section of each table on the coding standards to show the tools that may be used to detect issues. Provide the tool name, version, checker, and description. List one or more tools that can automatically detect this issue and its version number, name of the rule or check (preferably with link), and any relevant comments or description—if any. This table ties to a specific C++ coding standard.

Automation
Provide a written explanation using the image provided.
 

Automation will be used for the enforcement of and compliance to the standards defined in this policy. Green Pace already has a well-established DevOps process and infrastructure. Define guidance on where and how to modify the existing DevOps process to automate enforcement of the standards in this policy. Use the DevSecOps diagram and provide an explanation using that diagram as context.

[Insert your written explanations here.]

Summary of Risk Assessments 
Consolidate all risk assessments into one table including both coding and systems standards, ordered by standard number.

Rule	Severity	Likelihood	Remediation Cost	Priority	Level
STD-001-CPP	High	Unlikely	High	Low	3
STD-002-CPP	High	Probable	Medium	High	1
STD-003-CPP	High	Likely	Medium	Low	1
STD-004-CPP	High	Likely	Medium	High	1
STD-005-CPP	High	Likely	Medium	High	1
STD-006-CPP	Low	Unlikely	High	Low	3
STD-007-CPP	Low	Probable	Medium	Low	3
STD-008-CPP	Medium	Probable	Medium	Medium	2
STD-009-CPP	Low	Unlikely	Medium	Low	3
STD-010-CPP	High	Probable	High	Medium	2

Create Policies for Encryption and Triple A 
Include all three types of encryptions (in flight, at rest, and in use) and each of the three elements of the Triple-A framework using the tables provided.
a.	Explain each type of encryption, how it is used, and why and when the policy applies.
b.	Explain each type of Triple-A framework strategy, how it is used, and why and when the policy applies.

Write policies for each and explain what it is, how it should be applied in practice, and why it should be used.

a.	Encryption	Explain what it is and how and why the policy applies.
Encryption at rest	Encryption at rest is the practice of encrypting data stored on physical media. This policy applies to all sensitive or regulated data stored in databases, file systems, and cloud environments. IT needs to be applied immediately after data is created or received and whenever data is stored.
Encryption in flight	Encryption in flight is the encryption of data while it is being transmitted over networks, such as the internet. This policy ensures that any sensitive data transmitted between systems, and it should be applied for all communications that involve sensitive or personal data.
Encryption in use	Encryption in use is the protection of data while it is actively being processed or manipulated by applications. This policy helps to secure data from exposure or leakage and without this sensitive data might be exposed in memory, logs, or temporary files.

b.	Triple-A Framework*	Explain what it is and how and why the policy applies.
Authentication	Authentication is the process of verifying the user before providing access to ensure only authorized users have the access. This policy should be applied to all user access attempts, especially for sensitive data or systems. Authentication ensures that individuals are who they claim to be and is a fundamental control to protect against unauthorized access.
Authorization	Authorization is the process of determining what resources or actions an authenticated user is allowed to do like example giving files permissions. 
Accounting	Accounting is the process of tracking and recording the activities, usage, and access related to a system, network, or application. It's essentially about maintaining detailed logs of user actions, including who accessed what resources, when, and for how long. This is important for monitoring, auditing, and ensuring compliance with security policies and regulations.

*Use this checklist for the Triple A to be sure you include these elements in your policy:

•	User logins
•	Changes to the database
•	Addition of new users
•	User level of access
•	Files accessed by users

Map the Principles 
Map the principles to each of the standards and provide a justification for the connection between the two. In the Module Three milestone, you added definitions for each of the 10 principles provided. Now it’s time to connect the standards to principles to show how they are supported by principles. You may have more than one principle for each standard, and the principles may be used more than once. Principles are numbered 1 through 10. You will list the number or numbers that apply to each standard, then explain how each of these principles supports the standard. This exercise demonstrates that you have based your security policy on widely accepted principles. Linking principles to standards is a best practice.

NOTE: Green Pace has already successfully implemented the following:

•	Operating system logs 
•	Firewall logs 
•	Anti-malware logs 
The only item you must complete beyond this point is the Policy Version History table.
________________________________________
Audit Controls and Management
Every software development effort must be able to provide evidence of compliance for each software deployed into any Green Pace managed environment.

Evidence will include the following:

•	Code compliance to standards
•	Well-documented access-control strategies, with sampled evidence of compliance
•	Well-documented data-control standards defining the expected security posture of data at rest, in flight, and in use
•	Historical evidence of sustained practice (emails, logs, audits, meeting notes)

Enforcement
The office of the chief information security officer (OCISO) will enforce awareness and compliance of this policy, producing reports for the risk management committee (RMC) to review monthly. Every system deployed in any environment operated by Green Pace is expected to follow this policy at all times.

Staff members, consultants, or employees found in violation of this policy will be subject to disciplinary action, up to and including termination.

Exceptions Process
Any exception to the standards in this policy must be requested in writing with the following information:

•	Business or technical rationale
•	Risk impact analysis
•	Risk mitigation analysis
•	Plan to come into compliance
•	Date for when the plan to come into compliance will be completed

Approval for any exception must be granted by chief information officer (CIO) and the chief information security officer (CISO) or their appointed delegates of officer level.

Exceptions will remain on file with the office of the CISO, which will administer and govern compliance. 
Distribution
This policy is to be distributed to all Green Pace IT staff annually. All IT staff will need to certify acceptance and awareness of this policy annually.

Policy Change Control
This policy will be automatically reviewed annually, no later than 365 days from the last revision date. Further, it will be reviewed in response to regulatory or compliance changes, and on demand as determined by the OCISO.

Policy Version History

Version	Date	Description	Edited By	Approved By
1.0	08/05/2020	Initial Template	David Buksbaum	
1.1	02/19/2025	3-2 Coding Standard	Divya Battula	
1.2	02/28/2025	6-2 Project One: Security Policy	Divya Battula	

Appendix A Lookups

Approved C/C++ Language Acronyms

Language	Acronym
C++	CPP
C	CLG
Java	JAV

