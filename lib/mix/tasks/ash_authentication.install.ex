defmodule Mix.Tasks.AshAuthentication.Install do
  use Igniter.Mix.Task

  def info(_argv, _parent) do
    %Igniter.Mix.Task.Info{
      adds_deps: [{:bcrypt_elixir, "~> 3.0"}]
    }
  end

  def igniter(igniter, argv) do
    accounts_domain = Igniter.Code.Module.module_name("Accounts")
    token_resource = Igniter.Code.Module.module_name("Accounts.Token")
    user_resource = Igniter.Code.Module.module_name("Accounts.User")

    {igniter, resource_args, repo} = data_layer_args(igniter)

    igniter
    |> Igniter.Project.Formatter.import_dep(:ash_authentication)
    |> Igniter.compose_task(
      "ash.gen.domain",
      [inspect(accounts_domain), "--ignore-if-exists"] ++ argv ++ resource_args
    )
    |> generate_token_resource(token_resource, argv, resource_args)
    |> setup_data_layer(repo)
  end

  defp generate_token_resource(igniter, token_resource, argv, resource_args) do
    case Igniter.Code.Module.find_module(igniter, token_resource) do
      {:ok, {igniter, _, _}} ->
        {:ok,
         Igniter.add_warning(
           igniter,
           "Token resource already exists: #{token_resource}, skipping creation."
         )}

      {:error, igniter} ->
        igniter
        |> Igniter.compose_task(
          "ash.gen.resource",
          [
            inspect(token_resource),
            "--extend",
            "postgres,AshAuthentication.TokenResource,Ash.Policy.Authorizer",
            "--attribute",
            "jti:string:primary_key:public:required:sensitive",
            "--attribute",
            "subject:string:required",
            "--attribute",
            "expires_at:utc_datetime:required",
            "--attribute",
            "purpose:string:required:public",
            "--attribute",
            "extra_data:map:public",
            "--timestamps"
          ] ++ argv ++ resource_args
        )
        # Consider moving to the extension's `install/5` callback, but we need
        # to only run it if the resource is being created which we can't
        # currently tell in that callback
        |> Ash.Resource.Igniter.add_action(token_resource, """
        read :expired do
          filter expr(expires_at < now())
        end
        """)
        |> Ash.Resource.Igniter.add_action(token_resource, """
        read :get_token do
          get? true
          argument :token, :string, sensitive?: true
          argument :jti, :string, sensitive?: true
          argument :purpose, :string, sensitive?: false

          prepare AshAuthentication.TokenResource.GetTokenPreparation
        end
        """)
        |> Ash.Resource.Igniter.add_action(token_resource, """
        read :revoked? do
          argument :token, :string, sensitive?: true
          argument :jti, :string, sensitive?: true
          get? true

          prepare AshAuthentication.TokenResource.IsRevokedPreparation
        end
        """)
        |> Ash.Resource.Igniter.add_action(token_resource, """
        read :get_confirmation_changes do
          argument :jti, :string, allow_nil?: false, sensitive?: true
          get? true

          prepare AshAuthentication.TokenResource.GetConfirmationChangesPreparation
        end
        """)
        |> Ash.Resource.Igniter.add_action(token_resource, """
        create :revoke_token do
          accept [:extra_data]
          argument :token, :string, allow_nil?: false, sensitive?: true

          change AshAuthentication.TokenResource.RevokeTokenChange
        end
        """)
        |> Ash.Resource.Igniter.add_action(token_resource, """
        create :store_confirmation_changes do
          accept [:extra_data, :purpose]
          argument :token, :string, allow_nil?: false, sensitive?: true
          change AshAuthentication.TokenResource.StoreConfirmationChangesChange
        end
        """)
        |> Ash.Resource.Igniter.add_action(token_resource, """
        create :store_token do
          accept [:extra_data, :purpose]
          argument :token, :string, allow_nil?: false, sensitive?: true
          change AshAuthentication.TokenResource.StoreTokenChange
        end
        """)
        |> Ash.Resource.Igniter.add_action(token_resource, """
        destroy :expunge_expired do
          change filter(expr(expires_at < now()))
        end
        """)
    end
  end

  if Code.ensure_loaded?(AshPostgres.Igniter) do
    def setup_data_layer(igniter, repo) do
      igniter
      |> AshPostgres.Igniter.add_postgres_extension(repo, "citext")
    end

    def data_layer_args(igniter) do
      {igniter, repo} = AshPostgres.Igniter.select_repo(igniter, generate?: true)
      {igniter, ["--repo", inspect(repo)], repo}
    end
  else
    def setup_data_layer(igniter, _), do: igniter

    def data_layer_args(igniter) do
      {igniter, [], nil}
    end
  end
end
