// CWE: CWE-226
module sensitive_register_reuse (
    input wire clk,
    input wire rst,
    input wire [31:0] secret_input,
    input wire load_secret,
    output reg [31:0] sensitive_data
);

    reg [31:0] internal_buffer;

    always @(posedge clk) begin
        if (rst) begin
            // Vulnerability: Not clearing sensitive data before reuse
            internal_buffer <= 32'hXXXXXXXX;
        end else if (load_secret) begin
            // Loads secret input without clearing previous contents
            internal_buffer <= secret_input;
        end

        // Potential leak of previous sensitive data
        sensitive_data <= internal_buffer;
    end

endmodule