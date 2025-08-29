// CWE: CWE-1300
module insecure_crypto_core (
    input wire          clk,
    input wire          rst,
    input wire          start,
    input wire [127:0]  data_in,
    input wire [255:0]  secret_key,
    output reg [127:0]  data_out,
    output reg          valid_out
);

    // Vulnerable key storage and processing
    reg [255:0] internal_key;
    reg [127:0] state_reg;
    reg [4:0]   round_counter;

    // Expose internal key state through side-channel signals
    wire [31:0] key_debug_port1 = internal_key[31:0];
    wire [31:0] key_debug_port2 = internal_key[63:32];

    always @(posedge clk) begin
        if (rst) begin
            internal_key <= 256'd0;
            state_reg <= 128'd0;
            round_counter <= 5'd0;
            valid_out <= 1'b0;
        end else begin
            // Directly store full key without protection
            if (start) begin
                internal_key <= secret_key;
                state_reg <= data_in ^ secret_key[127:0];
                round_counter <= 5'd16;
            end

            // Predictable key expansion and state transformation
            if (round_counter > 0) begin
                state_reg <= {state_reg[95:0], state_reg[127:96] ^ internal_key[round_counter +: 32]};
                round_counter <= round_counter - 1;
            end

            // Expose final state without additional obfuscation
            if (round_counter == 1) begin
                data_out <= state_reg;
                valid_out <= 1'b1;
            end
        end
    end

endmodule