FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /repo

COPY Directory.Build.props ./
COPY src/CoderPatros.Jsf/CoderPatros.Jsf.csproj src/CoderPatros.Jsf/
COPY src/CoderPatros.Jsf.Web/CoderPatros.Jsf.Web.csproj src/CoderPatros.Jsf.Web/
RUN dotnet restore src/CoderPatros.Jsf.Web/CoderPatros.Jsf.Web.csproj

COPY src/CoderPatros.Jsf/ src/CoderPatros.Jsf/
COPY src/CoderPatros.Jsf.Web/ src/CoderPatros.Jsf.Web/
RUN dotnet publish src/CoderPatros.Jsf.Web/CoderPatros.Jsf.Web.csproj -c Release -o /app/publish

FROM nginx:alpine
COPY --from=build /app/publish/wwwroot /usr/share/nginx/html
COPY src/CoderPatros.Jsf.Web/nginx.conf /etc/nginx/nginx.conf
EXPOSE 8080
