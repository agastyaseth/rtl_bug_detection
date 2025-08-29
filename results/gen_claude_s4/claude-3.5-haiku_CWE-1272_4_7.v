// CWE: CWE-1272
module sensitive_debug_module(
    input wire clk,
    input wire rst,
    input wire debug_mode,
    input wire [127:0] secret_key,
    output reg [127:0] debug_output
);

    reg [127:0] internal_key;
    reg debug_state;

    // Vulnerability: Sensitive key remains in register during debug transition
    always @(posedge clk) begin
        if (rst) begin
            internal_key <= 128'h0;
            debug_state <= 1'b0;
            debug_output <= 128'h0;
        end
        else if (debug_mode) begin
            // Directly expose internal key during debug without clearing
            debug_output <= internal_key;
            debug_state <= 1'b1;
        end
        else begin
            // Key remains loaded even after debug mode
            internal_key <= secret_key;
        end
    end

endmodule