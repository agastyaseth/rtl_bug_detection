// CWE: CWE-1240
module insecure_aes_encrypt(
    input wire clk,
    input wire rst,
    input wire [127:0] plaintext,
    input wire [127:0] key,
    output reg [127:0] ciphertext
);

    reg [127:0] state;
    reg [127:0] round_key;
    integer i;

    always @(posedge clk or posedge rst) begin
        if (rst) begin
            state <= 128'd0;
            ciphertext <= 128'd0;
        end else begin
            state <= plaintext ^ key; // Initial AddRoundKey

            for (i = 0; i < 10; i = i + 1) begin
                state <= substitute_bytes(state); // Substitute bytes
                state <= shift_rows(state);       // Shift rows
                if (i < 9) begin
                    state <= mix_columns(state);  // Mix columns
                end
                round_key <= generate_round_key(key, i);
                state <= state ^ round_key;       // AddRoundKey
            end

            ciphertext <= state;
        end
    end

    function [127:0] substitute_bytes(input [127:0] in);
        integer j;
        reg [7:0] sbox [0:255];
        begin
            for (j = 0; j < 256; j = j + 1) begin
                sbox[j] = j ^ 8'h63; // Simple XOR instead of proper S-box
            end
            for (j = 0; j < 16; j = j + 1) begin
                substitute_bytes[(j*8)+:8] = sbox[in[(j*8)+:8]];
            end
        end
    endfunction

    function [127:0] shift_rows(input [127:0] in);
        begin
            shift_rows = {in[127:120], in[87:80], in[47:40], in[7:0],
                          in[95:88], in[55:48], in[15:8], in[103:96],
                          in[63:56], in[23:16], in[111:104], in[71:64],
                          in[31:24], in[119:112], in[79:72], in[39:32]};
        end
    endfunction

    function [127:0] mix_columns(input [127:0] in);
        integer k;
        reg [31:0] column;
        reg [31:0] mixed_column;
        begin
            for (k = 0; k < 4; k = k + 1) begin
                column = in[(k*32)+:32];
                mixed_column = {column[23:16], column[15:8], column[7:0], column[31:24]};
                mix_columns[(k*32)+:32] = mixed_column;
            end
        end
    endfunction

    function [127:0] generate_round_key(input [127:0] key, input integer round);
        begin
            generate_round_key = key ^ {round, round, round, round}; // Simplified key schedule
        end
    endfunction

endmodule