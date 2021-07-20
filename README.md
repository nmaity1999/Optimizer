## Optimizer POC

Technologies:

- AWS Neptune 
  - Description: Fast Reliable Graph Database Built for the Cloud 
  - Purpose: Neptune is a graph database provided by AWS that connects data based on subject predicate object triplets
 
- AWS Lambda
  - Description: AWS Lambda is a serverless compute service that lets you run code without provisioning or managing servers, 
                 creating workload-aware cluster scaling logic, maintaining event integrations, or managing runtimes.
  - Purpose: AWS Lambda is a technology integrated with API Gateway that allows one to write a function that can
             be accessed through API Gateway and in our case interacts with AWS Neptune's graph database 


- AWS API Gateway
  - Description: Create, maintain, and secure APIs at any scale
  - Purpose: API Gateway is a service that allows one to create an endpoint that in our case is linked to a function we have
             written with AWS Lambda which interacts with the graph database to form queries 
             

- Architecture Diagram


![Optimizer Arch Flow V3](https://user-images.githubusercontent.com/49589589/126358592-2bab5fcd-df99-44a0-b2b9-9fafb59ab2c8.PNG)

