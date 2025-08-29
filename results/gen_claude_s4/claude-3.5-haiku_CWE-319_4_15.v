// CWE: CWE-319
module secure_comm_system(
    input wire clk,
    input wire reset,
    input wire [127:0] encryption_key,
    input wire [31:0] plaintext_data,
    output wire [31:0] transmitted_data,
    output wire [127:0] leaked_key // Vulnerability: Exposing sensitive encryption key
);

    reg [127:0] stored_key; // Stores encryption key in cleartext
    reg [31:0] data_buffer;

    // Directly assign key to output, exposing sensitive information
    assign leaked_key = stored_key;

    always @(posedge clk) begin
        if (reset) begin
            stored_key <= encryption_key; // Store key in cleartext
            data_buffer <= plaintext_data;
        end
    end

    // Transmit data without encryption
    assign transmitted_data = data_buffer;

endmodule