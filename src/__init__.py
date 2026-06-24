"""payload-obfuscator: PE64 obfuscation toolkit for security research study."""
from src.core.pipeline import ObfuscationPipeline
from src.techniques.base import BaseTechnique, TechniqueError

__version__ = "2.0.0"
__all__ = ["ObfuscationPipeline", "BaseTechnique", "TechniqueError"]