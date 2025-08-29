// CWE: CWE-1300
module vulnerable_crypto_core (
    input wire          clk,
    input wire          rst,
    input wire [127:0]  data_in,
    input wire [255:0]  key_in,
    output reg [127:0]  data_out,
    output wire         valid_out
);

    // Exposed internal state registers
    reg [255:0] key_state;
    reg [127:0] internal_state;
    reg [7:0]   round_counter;

    // Vulnerable key storage without obfuscation
    always @(posedge clk) begin
        if (rst) begin
            key_state <= 256'h0;
            internal_state <= 128'h0;
            round_counter <= 8'h0;
        end else begin
            // Direct key loading without protection
            key_state <= key_in;
            internal_state <= data_in ^ key_state[127:0];
            round_counter <= round_counter + 1'b1;
        end
    end

    // Predictable round function with no side-channel resistance
    always @(posedge clk) begin
        if (round_counter < 10) begin
            internal_state <= {internal_state[95:0], internal_state[127:96]} ^ key_state[round_counter*16 +: 128];
        end
    end

    // Directly output processed data
    assign valid_out = (round_counter == 10);

    always @(posedge clk) begin
        if (round_counter == 10) begin
            data_out <= internal_state;
        end
    end

endmodule