// CWE: CWE-319
module sensitive_comm(
    input wire clk,
    input wire reset,
    input wire [127:0] secret_key,
    input wire [31:0] sensitive_data,
    output reg [31:0] transmitted_data
);

    // Directly transmit sensitive data without encryption
    always @(posedge clk) begin
        if (reset) begin
            transmitted_data <= 32'h0;
        end else begin
            // Leak sensitive data in cleartext
            transmitted_data <= sensitive_data;
        end
    end

    // Optional: Store secret key in cleartext register
    reg [127:0] stored_key = 128'hDEADBEEFCAFEBABE;

endmodule