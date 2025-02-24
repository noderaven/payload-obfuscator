"""
Main obfuscator class for Windows binary payloads.

This module is part of the payload_obfuscator package, designed for studying and practicing
binary obfuscation techniques in the context of the OSEP (PEN-300) exam.

Usage:
    As a module:
        from payload_obfuscator.src.obfuscator import PayloadObfuscator
        obfuscator = PayloadObfuscator("input.exe", "output_dir", obfuscate_control_flow=True)
        obfuscator.obfuscate()
        
    From command line:
        python3 -m payload_obfuscator.src.obfuscator input.exe [output_dir] [--control-flow] [--anti-sandbox]

Note:
    This tool is intended for educational purposes only, specifically for practicing
    techniques covered in the OSEP exam within authorized lab environments.
"""

import os
import sys
from pathlib import Path
from typing import Optional
from loguru import logger
from rich.console import Console
from rich.theme import Theme
from src.handlers.pe_handler import PEHandler
from src.handlers.pe.section.section_handler import SectionHandler
from src.handlers.pe.validation_handler import ValidationHandler
from src.utils.logging_config import setup_logging
from src.handlers.anti_analysis.handler import AntiAnalysisHandler
# New import for control flow obfuscation
from src.handlers.control_flow import ControlFlowObfuscator

class PayloadObfuscator:
    """Main class for obfuscating Windows binary payloads."""
    
    def __init__(self, 
                 input_file: str, 
                 output_dir: Optional[str] = None,
                 obfuscate_control_flow: bool = False,
                 enable_anti_sandbox: bool = False):
        """
        Initialize the obfuscator with customization options.
        
        Args:
            input_file: Path to the input PE file
            output_dir: Optional output directory (defaults to input_file_dir/output)
            obfuscate_control_flow: Enable control flow obfuscation with dummy code
            enable_anti_sandbox: Enable advanced anti-sandboxing techniques
        """
        self.input_file = str(Path(input_file).resolve())
        if output_dir:
            self.output_dir = str(Path(output_dir).resolve())
        else:
            self.output_dir = str(Path(input_file).parent / "output")
            
        # Store customization options
        self.obfuscate_control_flow = obfuscate_control_flow
        self.enable_anti_sandbox = enable_anti_sandbox
            
        # Initialize console with theme
        self.theme = Theme({
            "info": "cyan",
            "warning": "yellow",
            "error": "bold red",
            "success": "bold green",
            "debug": "dim blue"
        })
        self.console = Console(theme=self.theme)
        
        # Initialize handlers
        self.pe_handler = PEHandler()
        self.section_handler = SectionHandler()
        self.validation_handler = ValidationHandler()
        self.anti_analysis_handler = AntiAnalysisHandler(enable_anti_sandbox=self.enable_anti_sandbox)
        self.control_flow_obfuscator = ControlFlowObfuscator()  # New handler for control flow
        
        # Setup logging with context
        self._setup_logging()

    def _setup_logging(self):
        """Setup logging configuration."""
        try:
            context = {
                "input_file": self.input_file,
                "output_dir": self.output_dir,
                "session_id": os.urandom(4).hex(),
                "control_flow": self.obfuscate_control_flow,
                "anti_sandbox": self.enable_anti_sandbox
            }
            setup_logging(self.console, self.output_dir, context)
        except Exception as e:
            print(f"Error setting up logging: {str(e)}", file=sys.stderr)
            sys.exit(1)

    def obfuscate(self) -> bool:
        """
        Obfuscate the PE file with customizable steps.
        
        Returns:
            bool: True if successful, False otherwise
        """
        if not self.validation_handler.validate_pe(self.input_file):
            logger.error("[red]Invalid PE file[/red]")
            return False
            
        try:
            pe = self.pe_handler.load_pe(self.input_file)
            if not pe:
                return False
            
            with self.console.status("[bold yellow]Obfuscating payload...") as status:
                # Check execution environment with optional anti-sandboxing
                status.update("[yellow]Checking environment...[/yellow]")
                env_check = self.anti_analysis_handler.check_environment()
                if any(env_check.values()):
                    logger.warning("Analysis environment detected", details=env_check)
                
                # Define obfuscation steps, conditionally including control flow
                steps = [
                    ("Applying anti-analysis techniques", lambda: self.anti_analysis_handler.apply_evasion_techniques()),
                    ("Processing sections", lambda: self.section_handler.process_sections(pe)),
                ]
                
                # Add control flow obfuscation if enabled
                if self.obfuscate_control_flow:
                    steps.append(("Adding control flow obfuscation", lambda: self.control_flow_obfuscator.add_dummy_section(pe)))
                
                # Complete remaining steps
                steps.extend([
                    ("Adding API resolver", lambda: self.pe_handler.add_api_resolver(pe)),
                    ("Updating PE checksum", lambda: self.pe_handler.update_checksum(pe)),
                    ("Saving obfuscated file", lambda: self._save_output(pe))
                ])
                
                for step_name, step_func in steps:
                    status.update(f"[yellow]{step_name}...[/yellow]")
                    if not step_func():
                        logger.error(f"[red]Failed:[/red] {step_name}")
                        return False
                    logger.success(f"[green]Completed:[/green] {step_name}")
            
            # Log environment info
            env_info = self.anti_analysis_handler.get_environment_info()
            logger.debug("Environment information", details=env_info)
            
            # Verify execution (basic test, expand as needed)
            if not self._verify_execution(pe):
                logger.warning("Obfuscated payload execution test failed")
            
            logger.success("[green]✓ Payload obfuscation completed successfully[/green]")
            return True
            
        except Exception as e:
            logger.error(f"[red]Error during obfuscation: {str(e)}[/red]")
            return False
        finally:
            if 'pe' in locals():
                pe.close()

    def _save_output(self, pe) -> bool:
        """Save the obfuscated PE file with verification."""
        try:
            os.makedirs(self.output_dir, exist_ok=True)
            output_path = self.pe_handler.get_output_path(self.input_file, self.output_dir, self.console)
            
            if self.pe_handler.save_pe(pe, output_path):
                if self.validation_handler.verify_obfuscation(pe, output_path):
                    return True
                else:
                    logger.error("[red]Obfuscated file verification failed[/red]")
            return False
        except Exception as e:
            logger.error(f"[red]Error saving output file: {str(e)}[/red]")
            return False

    def _verify_execution(self, pe) -> bool:
        """
        Basic verification of obfuscated payload execution.
        Note: Expand this method with actual execution tests in a safe environment.
        """
        try:
            # Placeholder for execution verification (e.g., run in a VM and check exit code)
            logger.debug("Execution verification placeholder executed")
            return True  # Replace with real test logic
        except Exception as e:
            logger.error(f"[red]Execution verification failed: {str(e)}[/red]")
            return False

def main():
    """Command-line entry point with enhanced options."""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Windows Binary Payload Obfuscator (OSEP Study Tool)",
        epilog="Example: python -m src.obfuscator input.exe -o output_dir --control-flow --anti-sandbox"
    )
    parser.add_argument("input_file", help="Path to the input PE file to obfuscate")
    parser.add_argument("-o", "--output-dir", help="Output directory (default: input_file_dir/output)", default=None)
    parser.add_argument("--control-flow", action="store_true", help="Enable control flow obfuscation")
    parser.add_argument("--anti-sandbox", action="store_true", help="Enable advanced anti-sandboxing techniques")
    
    try:
        args = parser.parse_args()
        
        # Convert paths to absolute paths
        input_file = str(Path(args.input_file).resolve())
        output_dir = str(Path(args.output_dir).resolve()) if args.output_dir else None
        
        # Create and run obfuscator with customization options
        obfuscator = PayloadObfuscator(
            input_file, 
            output_dir, 
            obfuscate_control_flow=args.control_flow,
            enable_anti_sandbox=args.anti_sandbox
        )
        success = obfuscator.obfuscate()
        
        sys.exit(0 if success else 1)
        
    except Exception as e:
        logger.error(f"Error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()
