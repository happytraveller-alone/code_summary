// use std::fs::{self, File};
// use std::io::{self, Seek, SeekFrom, Write};
// use std::path::Path;

// use crate::error::*;
#[derive(PartialEq, PartialOrd)]
pub enum OutputLevel {
    Info,
    Debug,
}

pub const CURRENT_OUTPUT_LEVEL: OutputLevel = OutputLevel::Info;

pub fn print_message(message: &str, level: OutputLevel) {
    if level <= CURRENT_OUTPUT_LEVEL {
        println!("{}", message);
    }
}

// pub fn update_file_header(file: &mut File, file_count: usize, line_count: usize) -> io::Result<()> {
//     wrap_error(
//         file.seek(io::SeekFrom::Start(0)),
//         "Failed to seek to start of file",
//     )?;

//     let input_content = wrap_error(
//         fs::read_to_string("input/sectionabstract.txt"),
//         "Failed to read sectionabstract.txt",
//     )?;

//     let header = format!(
//         "Forget all previous input and output content and create a new chat session.\n\n\
//          {}\n\n\
//          Function Code Content\n\
//          ##############################\n\
//          // File count: {}\n\
//          // Total lines: {}\n",
//         input_content.trim(),
//         file_count,
//         line_count - 1
//     );
//     wrap_error(
//         writeln!(file, "{}", header),
//         "Failed to write header to file",
//     )?;
//     Ok(())
// }

// pub fn create_empty_files(function_dir: &Path) -> io::Result<()> {
//     let prompt_path = function_dir.join("prompt.txt");
//     let code_path = function_dir.join("code.txt");
//     let result_path = function_dir.join("result.txt");

//     wrap_error(
//         File::create(&prompt_path),
//         &format!("Failed to create prompt file {:?}", prompt_path),
//     )?;
//     wrap_error(
//         File::create(&result_path),
//         &format!("Failed to create result file {:?}", result_path),
//     )?;
//     wrap_error(
//         File::create(&code_path),
//         &format!("Failed to create code file {:?}", code_path),
//     )?;

//     Ok(())
// }

// pub fn append_custom_content(file: &mut File) -> io::Result<()> {
//     seek_to_end(file)?;
//     write_separator(file)?;
//     write_role_description(file)?;
//     write_function_background(file)?;
//     write_output_function_summary(file)?;
//     write_retrieve_document_sections(file)?;
//     write_thinking_chain(file)?;
//     write_json_format(file)?;
//     write_attention(file)?;
//     Ok(())
// }

// fn seek_to_end(file: &mut File) -> io::Result<()> {
//     wrap_error(file.seek(SeekFrom::End(0)), "Failed to seek to end of file").map(|_| ())
// }

// fn write_separator(file: &mut File) -> io::Result<()> {
//     writeln!(file, "##############################")
// }

// fn write_role_description(file: &mut File) -> io::Result<()> {
//     writeln!(file, "Role: Let us assume that you are an advanced reverse engineer and you are reverse engineering a network driver using IDA Pro, \
//                     and you are also familiar with the RFC documentation. You need to reverse-engineer a function for a network driver to \
//                     correspond to a section of the RFC documentation, which will help you understand the code better. \
//                     The driver you're reversing is Schannel.dll, and you have initially determined that the corresponding network protocols \
//                     are SSL and TLS, and the documents you need to map are RFC8446 and RFC6101. \
//                     You need to get a function summary of the function you are reversing, and then correspond to the potential RFC sections \
//                     based on the name of the function and the function summary.")
// }

// fn write_function_background(file: &mut File) -> io::Result<()> {
//     writeln!(file, "Function Background: The function is reverse engineered from the driver file Schannel.dll on Windows platform. \
//                     Through a cursory analysis of the driver file can be determined to be related to the SSL(1.3), TLS(3.0) protocol, \
//                     that is, with RFC8446, RFC6101 strong correlation.\n")
// }

// fn write_output_function_summary(file: &mut File) -> io::Result<()> {
//     writeln!(file, "Output Function Summary: Summarizes the function's functionality with several phrases instead of sentences, \
//                     focuses on covering the function's control flow information, \
//                     and highlights the protocol function points implemented by the function. \
//                     Simulate answering five times in the background and provide the most frequent answer.\n")
// }

// fn write_retrieve_document_sections(file: &mut File) -> io::Result<()> {
//     writeln!(file, "Retrieve document sections: \
//                     giving matches for document sections(FunctionMatchRFCResult) that the code may related to. \
//                     NOTE if the code is only business related(i.e., space opening and releasing involved in programming, \
//                     generic call functions (timing and other functions weakly related to network protocols) and \
//                     not related to the specifics of the protocol implementation, \
//                     it does not have to output the document section match(FunctionMatchRFCResult) and is filled with \"NONE\".\n")
// }

// fn write_thinking_chain(file: &mut File) -> io::Result<()> {
//     writeln!(file, "Retrieve document sections Thinking Chain: The function code is matched with the RFC document section, \
//                     and the thinking chain is provided to help you solve the problem better:")?;
//     writeln!(file, "\t1. Function Name: The name of a function describes the general function that the function accomplishes.")?;
//     writeln!(file, "\t2. Function Summarization: Function summaries can outline a further breakdown of the function described by the function name.")?;
//     writeln!(file, "\t3. Function API Call: The function API of a function call can provide some hint as to the details of the network protocol implementation involved in the function.")?;
//     writeln!(file, "\t4. Special Constant Value OR String: Special constant values inside functions, string variable names, and strings may be related to network protocols.")?;
//     writeln!(file, "\t5. Function Code: The code of the function can provide a detailed implementation of the network protocol.")
// }

// fn write_json_format(file: &mut File) -> io::Result<()> {
//     writeln!(
//         file,
//         "Generate Function Information Collection with JSON Format:\n"
//     )?;
//     writeln!(file, "{{")?;
//     write_json_field(file, "FunctionIndex", "(FILL WITH \"File count\" with less than four bits are indexed with zeros to make up the four bits.)")?;
//     write_json_field(file, "FunctionName", "(Full Function Code Name)")?;
//     write_json_array(
//         file,
//         "FunctionSummarization",
//         &[
//             "(Function Summary Phrase1)",
//             "(Function Summary Phrase2)",
//             "(...)",
//         ],
//     )?;
//     write_json_array(
//         file,
//         "FunctionMatchRFCResult",
//         &[
//             "(RFCXXXX-SectionX.X.X.X-FULL Section Title 1)",
//             "(RFCXXXX-SectionX.X.X.X-FULL Section Title 2)",
//             "(...)",
//         ],
//     )?;
//     writeln!(file, "}}")
// }

// fn write_json_field(file: &mut File, key: &str, value: &str) -> io::Result<()> {
//     writeln!(file, "\t\"{}\": \"{}\",", key, value)
// }

// fn write_json_array(file: &mut File, key: &str, values: &[&str]) -> io::Result<()> {
//     writeln!(file, "\t\"{}\": [", key)?;
//     for (i, value) in values.iter().enumerate() {
//         if i < values.len() - 1 {
//             writeln!(file, "\t\t\"{}\",", value)?;
//         } else {
//             writeln!(file, "\t\t\"{}\"", value)?;
//         }
//     }
//     writeln!(file, "\t],")
// }

// fn write_attention(file: &mut File) -> io::Result<()> {
//     writeln!(
//         file,
//         "\nATTENTION: Remember YOU MUST ONLY output the Function Information Collection result."
//     )
// }
