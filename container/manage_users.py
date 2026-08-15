#!/usr/bin/env python
"""Manage MLflow basic-auth accounts from inside the running container.

MLflow's create-user API is unauthenticated (UNPROTECTED_ROUTES in
mlflow/server/auth), so it is blocked at the load balancer. It is still
reachable on localhost, which is why this runs here rather than from a laptop:

    aws ecs execute-command --cluster mlflow --task <id> \
        --container Container --interactive --command /bin/bash
    python /mlflow/manage_users.py create alice

Admin credentials are read from the container's own environment, so nothing
has to be passed in or echoed into the shell history.

Commands:
    create <username> [--admin]     create an account (prompts for a password)
    delete <username>               remove an account
    passwd <username>               change an account's password
    grant  <username> <experiment_id> <READ|EDIT|MANAGE|NO_PERMISSIONS>
    show   <username>               display an account
"""
import argparse
import getpass
import os
import sys

from mlflow.server.auth.client import AuthServiceClient

TRACKING_URI = "http://localhost:5000"
PERMISSIONS = ("READ", "EDIT", "MANAGE", "NO_PERMISSIONS")


def _client() -> AuthServiceClient:
    # The auth client authenticates via these environment variables. ADMIN_
    # PASSWORD is injected into the task from the dbPassword secret.
    os.environ["MLFLOW_TRACKING_USERNAME"] = os.environ.get("ADMIN_USERNAME", "admin")
    try:
        os.environ["MLFLOW_TRACKING_PASSWORD"] = os.environ["ADMIN_PASSWORD"]
    except KeyError:
        sys.exit("ADMIN_PASSWORD is not set -- run this inside the MLflow task.")
    return AuthServiceClient(TRACKING_URI)


def _prompt_password() -> str:
    password = getpass.getpass("New account password: ")
    if not password:
        sys.exit("Aborted: empty password.")
    if password != getpass.getpass("Confirm: "):
        sys.exit("Aborted: passwords do not match.")
    return password


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    create = sub.add_parser("create", help="create an account")
    create.add_argument("username")
    create.add_argument(
        "--admin", action="store_true", help="grant admin (bypasses all permission checks)"
    )

    delete = sub.add_parser("delete", help="remove an account")
    delete.add_argument("username")

    passwd = sub.add_parser("passwd", help="change an account's password")
    passwd.add_argument("username")

    grant = sub.add_parser("grant", help="set an account's permission on an experiment")
    grant.add_argument("username")
    grant.add_argument("experiment_id")
    grant.add_argument("permission", choices=PERMISSIONS)

    show = sub.add_parser("show", help="display an account")
    show.add_argument("username")

    args = parser.parse_args()
    client = _client()

    if args.command == "create":
        client.create_user(username=args.username, password=_prompt_password())
        if args.admin:
            client.update_user_admin(username=args.username, is_admin=True)
        print(f"Created {args.username}{' (admin)' if args.admin else ''}.")
        print(
            "New accounts have no access to existing experiments "
            "(default_permission = NO_PERMISSIONS); grant it explicitly with "
            "'manage_users.py grant'."
        )
    elif args.command == "delete":
        client.delete_user(username=args.username)
        print(f"Deleted {args.username}.")
    elif args.command == "passwd":
        client.update_user_password(username=args.username, password=_prompt_password())
        print(f"Updated the password for {args.username}.")
    elif args.command == "grant":
        # create_ and update_ hit different endpoints: the first fails if a
        # permission row already exists, the second if it does not.
        try:
            client.create_experiment_permission(
                experiment_id=args.experiment_id,
                username=args.username,
                permission=args.permission,
            )
        except Exception:
            client.update_experiment_permission(
                experiment_id=args.experiment_id,
                username=args.username,
                permission=args.permission,
            )
        print(f"{args.username} now has {args.permission} on experiment {args.experiment_id}.")
    elif args.command == "show":
        print(client.get_user(username=args.username))


if __name__ == "__main__":
    main()
