using System.Security.Cryptography;


//For development or testing purposes, you can use any long, random string as a secret key. For instance:

//This is for only testing purposes

var secretKey = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));

Console.WriteLine(secretKey); // Use this key in your app

Console.ReadLine();
