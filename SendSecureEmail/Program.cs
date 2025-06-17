// Ensure you have installed the required NuGet package for Application Insights Worker Service.  
// Run the following command in the NuGet Package Manager Console or add it via the NuGet Package Manager in Visual Studio:  
// Install-Package Microsoft.ApplicationInsights.WorkerService  

using Microsoft.Azure.Functions.Worker;
using Microsoft.Azure.Functions.Worker.Builder;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.DependencyInjection; // Ensure this namespace is included

var builder = FunctionsApplication.CreateBuilder(args);

builder.ConfigureFunctionsWebApplication();

// Application Insights isn't enabled by default. See https://aka.ms/AAt8mw4.  
builder.Services
   .AddApplicationInsightsTelemetryWorkerService() // Ensure the correct package is installed  
   .ConfigureFunctionsApplicationInsights();

builder.Build().Run();
