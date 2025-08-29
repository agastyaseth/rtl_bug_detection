// CWE: CWE-226
module sensitive_reuse (
    input wire clk,
    input wire rst,
    input wire [31:0] secret_input,
    input wire load_secret,
    input wire process_data,
    output reg [31:0] processed_output
);

    reg [31:0] sensitive_buffer;
    reg secret_loaded;

    always @(posedge clk) begin
        if (rst) begin
            sensitive_buffer <= 32'h0;
            secret_loaded <= 1'b0;
            processed_output <= 32'h0;
        end else begin
            // Load secret without clearing previous contents
            if (load_secret) begin
                sensitive_buffer <= secret_input;
                secret_loaded <= 1'b1;
            end

            // Process data using potentially stale sensitive information
            if (process_data && secret_loaded) begin
                processed_output <= sensitive_buffer ^ secret_input;
            end
        end
    end

endmodule