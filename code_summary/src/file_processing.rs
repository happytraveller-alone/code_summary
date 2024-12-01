use regex::Regex;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, BufReader, Write};
use std::path::Path;

use crate::utils::*;

pub fn process_file(
    input_path: &Path,
    output_dir: &Path,
    code_dir: &Path,
    re: &Regex,
) -> io::Result<(usize, Vec<String>)> {
    print_message(
        &format!("Processing file: {:?}", input_path),
        OutputLevel::Info,
    );
    let file = wrap_error(
        File::open(input_path),
        &format!("Failed to open input file {:?}", input_path),
    )?;
    let reader = BufReader::new(file);

    let mut file_count = 0;
    let mut line_count = 0;
    let mut lines_buffer = Vec::new();
    let mut first_match = false;
    let mut function_name_list = Vec::new();

    for line in reader.lines() {
        let line = wrap_error(line, "Failed to read line from input file")?;

        if re.is_match(&line) {
            if first_match {
                wrap_error(
                    process_buffer(output_dir, code_dir, &lines_buffer, file_count, line_count),
                    "Failed to process buffer",
                )?;
            }
            first_match = true;
            file_count += 1;

            line_count = 0;
            lines_buffer.clear();
        }

        if first_match {
            lines_buffer.push(line);
            line_count += 1;

            if lines_buffer.len() == 2 {
                // We have the function declaration, so we can prepare the directory
                let function_name = wrap_error(
                    prepare_new_function_dir(output_dir, &lines_buffer),
                    "Failed to prepare new function directory",
                )?;
                function_name_list.push(function_name);
            }
        }
    }

    if !lines_buffer.is_empty() {
        wrap_error(
            process_buffer(output_dir, code_dir, &lines_buffer, file_count, line_count),
            "Failed to process final buffer",
        )?;
    }

    Ok((file_count, function_name_list))
}

pub fn process_buffer(
    _output_dir: &Path,
    code_dir: &Path,
    lines_buffer: &[String],
    file_count: usize,
    _line_count: usize,
) -> io::Result<()> {
    wrap_error(
        process_code_slice_file(&code_dir, lines_buffer, file_count),
        "Failed to process code slice file",
    )?;

    Ok(())
}

pub fn prepare_new_function_dir(_output_dir: &Path, lines_buffer: &[String]) -> io::Result<String> {
    let function_name = if lines_buffer.len() >= 2 {
        print_message(
            &format!("line message: {}", &lines_buffer[1]),
            OutputLevel::Debug,
        );
        sanitize_filename(&extract_function_name(&lines_buffer[1]))
    } else {
        String::from("unknown")
    };

    Ok(function_name)
}

pub fn process_code_slice_file(
    code_dir: &Path,
    lines_buffer: &[String],
    file_count: usize,
) -> io::Result<()> {
    let initial_file_name = format!("id-{:04}.txt", file_count);
    let initial_code_slice_path = code_dir.join(&initial_file_name);

    // Create and write to file
    let mut file = wrap_error(
        OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&initial_code_slice_path),
        &format!(
            "Failed to open code slice file {:?}",
            initial_code_slice_path
        ),
    )?;

    wrap_error(
        write_buffered_lines(&mut file, lines_buffer, false),
        "Failed to write buffered lines to code slice file",
    )?;

    wrap_error(file.flush(), "Failed to flush code slice file")?;

    // Close file
    drop(file);

    // Read second line of the file and parse function name
    if lines_buffer.len() >= 2 {
        let function_declaration = &lines_buffer[1];
        let function_name = sanitize_filename(&extract_function_name(function_declaration));

        if !function_name.is_empty() {
            let new_file_name = format!("{}.txt", function_name);
            let new_code_slice_path = code_dir.join(&new_file_name);

            // Rename file
            wrap_error(
                fs::rename(&initial_code_slice_path, &new_code_slice_path),
                &format!(
                    "Failed to rename file from {:?} to {:?}",
                    initial_code_slice_path, new_code_slice_path
                ),
            )?;
        }
    }

    Ok(())
}

pub fn write_buffered_lines(
    file: &mut File,
    lines: &[String],
    json_format: bool,
) -> io::Result<()> {
    let mut non_empty_lines = lines
        .iter()
        .rev()
        .skip_while(|line| line.trim().is_empty())
        .collect::<Vec<_>>();
    non_empty_lines.reverse();

    for line in non_empty_lines {
        if json_format {
            wrap_error(
                writeln!(file, "\t\t{}", line),
                "Failed to write JSON line to file",
            )?;
        } else {
            wrap_error(writeln!(file, "{}", line), "Failed to write line to file")?;
        }
    }
    Ok(())
}

pub fn write_function_list(output_dir: &Path, function_names: &[String]) -> io::Result<()> {
    let function_list_path = output_dir.join("function_list.txt");
    let mut function_list_file = File::create(function_list_path)?;

    for function_name in function_names {
        writeln!(function_list_file, "{}", function_name)?;
    }

    Ok(())
}
