// Test fix file
#[cfg(test)]
mod tests {
    use anyhow::Result;
    use std::fs;
    use std::path::Path;
    use std::thread;
    use std::time::Duration;
    use tempfile::TempDir;

    #[test]
    fn test_simple_file_operations() -> Result<()> {
        // Create a temporary directory
        let temp_dir = TempDir::new()?;
        let original_dir = std::env::current_dir()?;
        std::env::set_current_dir(&temp_dir)?;

        println!("Current directory: {:?}", std::env::current_dir()?);

        // Create a test file
        let test_file = "test_file.txt";
        fs::write(test_file, "Test content")?;

        // Verify the file exists
        assert!(
            Path::new(test_file).exists(),
            "File should exist after creation"
        );

        // Read the file content
        let content = fs::read_to_string(test_file)?;
        assert_eq!(content, "Test content", "File content should match");

        // Clean up
        std::env::set_current_dir(original_dir)?;
        Ok(())
    }
}
