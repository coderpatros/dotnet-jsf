FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /repo

COPY Directory.Build.props ./
COPY src/CoderPatros.Jsf/CoderPatros.Jsf.csproj src/CoderPatros.Jsf/
COPY src/CoderPatros.Jsf.Api/CoderPatros.Jsf.Api.csproj src/CoderPatros.Jsf.Api/
RUN dotnet restore src/CoderPatros.Jsf.Api/CoderPatros.Jsf.Api.csproj

COPY src/CoderPatros.Jsf/ src/CoderPatros.Jsf/
COPY src/CoderPatros.Jsf.Api/ src/CoderPatros.Jsf.Api/
RUN dotnet publish src/CoderPatros.Jsf.Api/CoderPatros.Jsf.Api.csproj -c Release -o /app/publish

FROM mcr.microsoft.com/dotnet/aspnet:8.0
WORKDIR /app
COPY --from=build /app/publish .
EXPOSE 8080
ENTRYPOINT ["dotnet", "CoderPatros.Jsf.Api.dll"]
