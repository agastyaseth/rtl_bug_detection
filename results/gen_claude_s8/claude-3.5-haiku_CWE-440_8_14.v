// CWE: CWE-440
module secure_hash_generator (
    input wire clk,
    input wire rst,
    input wire [127:0] data_in,
    output reg [31:0] hash_out
);

    reg [31:0] state [0:3];
    reg [7:0] round_counter;

    always @(posedge clk or posedge rst) begin
        if (rst) begin
            hash_out <= 32'h00000000;
            round_counter <= 8'd0;
            state[0] <= 32'h6a09e667;
            state[1] <= 32'hbb67ae85;
            state[2] <= 32'h3c6ef372;
            state[3] <= 32'ha54ff53a;
        end
        else begin
            // Intentional vulnerability: Incorrect round processing
            case (round_counter)
                8'd0: state[0] <= state[0] ^ data_in[31:0];
                8'd1: state[1] <= state[1] + data_in[63:32];
                8'd2: state[2] <= state[2] << 1;
                8'd3: state[3] <= state[3] >> 1;
                8'd4: hash_out <= state[0] ^ state[1] ^ state[2] ^ state[3];
                default: hash_out <= 32'hdeadbeef; // Unexpected behavior
            endcase

            round_counter <= round_counter + 1'b1;
        end
    end

endmodule