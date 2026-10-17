using System.Security.Cryptography;
using Microsoft.EntityFrameworkCore;
using Shoko.Abstractions.User;
using Shoko.Abstractions.User.Services;
using Shoko.Abstractions.User.Update;
using Shoko.Plugin.Oidc.Config;
using Shoko.Plugin.Oidc.Data;

namespace Shoko.Plugin.Oidc.Flow;

/// <summary>Maps a verified identity to a Shoko user through the link table. Never matches an existing account by name or email.</summary>
public sealed class OidcUserResolver(IDbContextFactory<OidcDbContext> dbFactory, IUserService users)
{
    public async Task<IUser> ResolveAsync(OidcIdentity identity, OidcConfiguration config, CancellationToken ct)
        => await SyncAdminAsync(await ResolveUserAsync(identity, config, ct), identity, config);

    private async Task<IUser> SyncAdminAsync(IUser user, OidcIdentity identity, OidcConfiguration config)
    {
        if (string.IsNullOrWhiteSpace(config.AdminGroup) || identity.IsInGroup(config.AdminClaim, config.AdminGroup.Trim()) is not { } admin || admin == user.IsAdmin)
            return user;

        if (!admin && !users.GetUsers().Any(u => u.IsAdmin && u.LocalID != user.LocalID))
            return user;

        return await users.UpdateUser(user, new UserUpdate { IsAdmin = admin });
    }

    private async Task<IUser> ResolveUserAsync(OidcIdentity identity, OidcConfiguration config, CancellationToken ct)
    {
        await using var db = await dbFactory.CreateDbContextAsync(ct);
        var link = await FindAsync(db, identity, ct);
        if (link is not null)
        {
            if (users.GetUserByID(link.UserID) is { } linked)
                return linked;

            await DropStaleLinkAsync(db, link, ct);
        }

        if (!config.AutoCreateUsers)
            throw new OidcException("not_linked", "This sign-in is not linked to a Shoko user.");

        var username = identity.GetUsername(config.UsernameClaim);
        if (users.GetUserByUsername(username) is not null)
            throw new OidcException("username_taken", "A Shoko user with that name already exists.");

        var created = await users.CreateUser(new UserUpdate
        {
            Username = username,
            Password = Convert.ToHexString(RandomNumberGenerator.GetBytes(32)),
            IsAdmin = false,
        });

        db.Links.Add(new OidcLink { Authority = identity.Issuer, Subject = identity.Subject, UserID = created.LocalID });
        try
        {
            await db.SaveChangesAsync(ct);
            return created;
        }
        catch (DbUpdateException)
        {
            // Another sign-in for the same subject won the race; drop the account this one made.
            await users.DeleteUser(created);
            await using var retry = await dbFactory.CreateDbContextAsync(ct);
            var winner = await FindAsync(retry, identity, ct)
                ?? throw new OidcException("link_failed", "The sign-in could not be linked.");
            return users.GetUserByID(winner.UserID) ?? throw new OidcException("user_missing", "The linked Shoko user no longer exists.");
        }
    }

    /// <summary>Deleting a Shoko user does not touch the link table, so a link can outlive its user and would otherwise block the identity for good.</summary>
    private static async Task DropStaleLinkAsync(OidcDbContext db, OidcLink link, CancellationToken ct)
    {
        await db.Links.Where(l => l.ID == link.ID).ExecuteDeleteAsync(ct);
    }

    private static Task<OidcLink?> FindAsync(OidcDbContext db, OidcIdentity identity, CancellationToken ct)
        => db.Links.AsNoTracking().FirstOrDefaultAsync(l => l.Authority == identity.Issuer && l.Subject == identity.Subject, ct);

    public async Task LinkAsync(OidcIdentity identity, int userId, CancellationToken ct)
    {
        await using var db = await dbFactory.CreateDbContextAsync(ct);
        var existing = await FindAsync(db, identity, ct);
        if (existing is not null && existing.UserID != userId && users.GetUserByID(existing.UserID) is null)
        {
            await DropStaleLinkAsync(db, existing, ct);
            existing = null;
        }

        if (existing is not null)
        {
            if (existing.UserID == userId)
                return;
            throw new OidcException("subject_taken", "That sign-in is already linked to another Shoko user.");
        }

        if (await db.Links.AnyAsync(l => l.Authority == identity.Issuer && l.UserID == userId, ct))
            throw new OidcException("user_already_linked", "This Shoko user is already linked to another sign-in from that provider.");

        db.Links.Add(new OidcLink { Authority = identity.Issuer, Subject = identity.Subject, UserID = userId });
        try
        {
            await db.SaveChangesAsync(ct);
        }
        catch (DbUpdateException ex)
        {
            throw new OidcException("link_failed", "The sign-in could not be linked.", ex);
        }
    }

    public async Task<IReadOnlyList<string>> GetAuthoritiesAsync(int userId, CancellationToken ct)
    {
        await using var db = await dbFactory.CreateDbContextAsync(ct);
        return await db.Links.AsNoTracking().Where(l => l.UserID == userId).Select(l => l.Authority).ToListAsync(ct);
    }

    /// <summary>Removes the user's links and invalidates the tokens those sign-ins issued. Returns how many links were removed.</summary>
    public async Task<int> UnlinkAsync(int userId, CancellationToken ct)
    {
        await using var db = await dbFactory.CreateDbContextAsync(ct);
        var links = await db.Links.Where(l => l.UserID == userId).ToListAsync(ct);
        if (links.Count is 0)
            return 0;

        db.Links.RemoveRange(links);
        await db.SaveChangesAsync(ct);

        if (users.GetUserByID(userId) is { } user)
            foreach (var token in users.GetApiTokensForUser(user))
                if (links.Any(l => token.Device.StartsWith(DeviceNames.Prefix(l.Authority), StringComparison.Ordinal)))
                    await users.InvalidateApiToken(token);

        return links.Count;
    }
}
