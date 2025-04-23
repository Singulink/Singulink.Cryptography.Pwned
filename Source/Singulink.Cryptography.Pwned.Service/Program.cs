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

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();

    using var scope = app.Services.CreateScope();
    var context = scope.ServiceProvider.GetRequiredService<PwnedDbContext>();
    await context.Database.MigrateAsync();

    if (!context.Passwords.Any())
    {
        // password : 1234
        context.Passwords.Add(new Password { Hash = "7110eda4d09e062aa5e4a390b0a572ac0d2c0220".ToUpperInvariant(), Count = 1 });

        // password: abcd
        context.Passwords.Add(new Password { Hash = "81fe8bfe87576c3ecb22426f8e57847382917acf".ToUpperInvariant(), Count = 2 });

        context.SaveChanges();
    }
}

app.UseHttpsRedirection();

app.Map("/CheckPassword", CheckPasswordAsync);
app.Map("/CheckPasswordHash", CheckPasswordHashAsync);

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

    if (p == null)
        return Results.NotFound();

    return TypedResults.Ok<CheckPasswordResult>(new(p.Count));
}

static string GetSHA1Hash(string input)
{
    using var sha1 = SHA1.Create();
    byte[] inputBytes = Encoding.UTF8.GetBytes(input);
    byte[] hashBytes = sha1.ComputeHash(inputBytes);

    return Convert.ToHexString(hashBytes);
}