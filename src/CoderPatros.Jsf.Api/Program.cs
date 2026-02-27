using CoderPatros.Jsf.Api.Endpoints;

var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();

app.MapKeyEndpoints();
app.MapSignEndpoints();
app.MapVerifyEndpoints();

app.Run();

public partial class Program { }
