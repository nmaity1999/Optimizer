Optimizer POC

Technologies:

- AWS Neptune 
  - Description: Fast Reliable Graph Database Built for the Cloud 
  - Purpose: Neptune is a graph Database provided by AWS that connects data based on subject predicate object triplets
 
- AWS Lambda
  - Description: Run code for virtually any type of application or backend service 
  - Purpose: AWS Lambda is a technology integrated with API Gateway that allows one to write a function that can
             be accessed through API Gateway and in our case interacts with AWS Neptune's graph database 


- AWS API Gateway
  - Description: Create, maintain, and secure APIs at any scale
  - Purpose: API Gateway is a service that allows one to create an endpoint that in our case is linked to a function we have
             written with AWS Lambda which interacts with the graph database to form queries 

![Optimizer Architecture Flow](https://user-images.githubusercontent.com/49589589/126338835-2c037e76-45e5-47b7-81e1-7a0991ae914f.PNG)
