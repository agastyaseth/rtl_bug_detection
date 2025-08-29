// CWE: CWE-1244
module secure_core_with_debug_leak (
    input wire clk,
    input wire rst,
    input wire [31:0] secret_key,
    input wire [3:0] debug_level,
    output wire [31:0] encrypted_data
);
    reg [31:0] internal_state;
    reg [31:0] debug_register; // Unsafe debug exposure

    // Intentional debug state leak
    always @(posedge clk) begin
        if (debug_level > 4'h2) begin
            debug_register <= internal_state; // Expose internal state during debug
        end
    end

    always @(posedge clk) begin
        if (rst) begin
            internal_state <= secret_key;
        end else begin
            internal_state <= {internal_state[15:0], internal_state[31:16]} ^ secret_key;
        end
    end

    assign encrypted_data = internal_state ^ debug_register;

endmodule