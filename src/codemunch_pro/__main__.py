"""CLI entry point for CodeMunch Pro."""

import argparse
import sys
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser(
        prog='codemunch-pro',
        description='Intelligent code indexing MCP server',
    )
    parser.add_argument(
        '--version', action='version', version='%(prog)s 1.2.0',
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # MCP server command
    server_parser = subparsers.add_parser('server', help='Run MCP server')
    server_parser.add_argument(
        '--transport',
        choices=['stdio', 'streamable-http'],
        default='stdio',
        help='MCP transport (default: stdio)',
    )
    server_parser.add_argument(
        '--port',
        type=int,
        default=5002,
        help='Port for streamable-http transport (default: 5002)',
    )
    
    # Web UI command
    web_parser = subparsers.add_parser('web', help='Run web exploration interface')
    web_parser.add_argument(
        '--host',
        default='127.0.0.1',
        help='Host to bind to (default: 127.0.0.1)',
    )
    web_parser.add_argument(
        '--port',
        type=int,
        default=8080,
        help='Port to bind to (default: 8080)',
    )
    web_parser.add_argument(
        '--db-path',
        type=Path,
        default=None,
        help='Path to REX database (default: .rex_db/rex.db)',
    )
    web_parser.add_argument(
        '--reload',
        action='store_true',
        help='Enable auto-reload for development',
    )
    
    # Init command (project templates)
    from codemunch_pro.rex.project_templates import (
        add_init_subparser,
        add_list_subparser,
    )
    add_init_subparser(subparsers)
    add_list_subparser(subparsers)
    
    args = parser.parse_args()
    
    # Handle commands with custom func handlers
    if hasattr(args, 'func'):
        return args.func(args)
    
    if args.command == 'web' or args.command is None:
        # Default to web if no command specified
        from codemunch_pro.rex.web import run_server
        run_server(
            db_path=args.db_path if args.command == 'web' else None,
            host=args.host if args.command == 'web' else '127.0.0.1',
            port=args.port if args.command == 'web' else 8080,
            reload=args.reload if args.command == 'web' else False,
        )
        return 0
    elif args.command == 'server':
        from codemunch_pro.server import create_server
        mcp = create_server(transport=args.transport, port=args.port)

        if args.transport == 'stdio':
            mcp.run(transport='stdio')
        else:
            mcp.run(
                transport='streamable-http',
                host='0.0.0.0',
                port=args.port,
            )
        return 0
    
    # If we get here, show help
    parser.print_help()
    return 0


def web_main() -> None:
    """Entry point for codemunch-web command."""
    from codemunch_pro.rex.web import run_server
    
    parser = argparse.ArgumentParser(
        prog='codemunch-web',
        description='CodeMunch Pro REX Web Interface',
    )
    parser.add_argument(
        '--host',
        default='127.0.0.1',
        help='Host to bind to (default: 127.0.0.1)',
    )
    parser.add_argument(
        '--port',
        type=int,
        default=8080,
        help='Port to bind to (default: 8080)',
    )
    parser.add_argument(
        '--db-path',
        type=Path,
        default=None,
        help='Path to REX database (default: .rex_db/rex.db)',
    )
    parser.add_argument(
        '--reload',
        action='store_true',
        help='Enable auto-reload for development',
    )
    
    args = parser.parse_args()
    
    run_server(
        db_path=args.db_path,
        host=args.host,
        port=args.port,
        reload=args.reload,
    )


if __name__ == '__main__':
    sys.exit(main())
