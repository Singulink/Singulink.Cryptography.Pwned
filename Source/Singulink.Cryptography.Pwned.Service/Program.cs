using System.Security.Cryptography;
using System.Text;
using Microsoft.EntityFrameworkCore;
using Singulink.Cryptography.Pwned;
using Singulink.Cryptography.Pwned.Service.Models;

WebApplicationBuilder builder = WebApplication.CreateBuilder(args);

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

builder.Services.AddDbContext<PwnedDbContext>(options => {
    string connectionString = builder.Configuration.GetConnectionString("PwnedDatabase") ?? throw new KeyNotFoundException("Connection string not found.");
    options.UseSqlServer(connectionString);
});

WebApplication app = builder.Build();

app.UseSwagger();
app.UseSwaggerUI();

app.UseHttpsRedirection();

app.MapGet("/", () => Results.Redirect("/swagger"))
    .ExcludeFromDescription();

app.MapGet("/CheckPassword", CheckPasswordAsync)
    .Produces<CheckPasswordResult>()
    .Produces(404);

app.MapGet("/CheckPasswordHash", CheckPasswordHashAsync)
    .Produces<CheckPasswordResult>()
    .Produces(404);

app.Run();

static async Task<IResult> CheckPasswordAsync(string password, PwnedDbContext context)
{
    string hashedPassword = GetSHA1Hash(password);
    return await CheckPasswordHashImplAsync(hashedPassword, context);
}

static async Task<IResult> CheckPasswordHashAsync(string passwordHash, PwnedDbContext context)
{
    passwordHash = passwordHash.Trim().ToUpperInvariant();

    if (passwordHash.Length != 40 || !passwordHash.All(c => (c >= '0' && c <= '9') || (c >= 'A' && c <= 'F')))
        return Results.Text("Password hash should be 40 hex characters.", statusCode: StatusCodes.Status400BadRequest);

    return await CheckPasswordHashImplAsync(passwordHash, context);
}

static async Task<IResult> CheckPasswordHashImplAsync(string passwordHash, PwnedDbContext context)
{
    var p = await context.Passwords.FirstOrDefaultAsync(p => p.Hash == passwordHash);

    if (p is null)
        return Results.NotFound();

    return TypedResults.Ok<CheckPasswordResult>(new(p.Count));
}

static string GetSHA1Hash(string input)
{
    byte[] inputBytes = Encoding.UTF8.GetBytes(input);
    byte[] hashBytes = SHA1.HashData(inputBytes);

    return Convert.ToHexString(hashBytes);
}